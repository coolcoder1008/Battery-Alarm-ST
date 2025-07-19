const functions = require('firebase-functions');
const { onRequest, onHttpRequest } = require('firebase-functions/v2/https');
const admin = require('firebase-admin');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const SchemaConnector = require('./lib/SchemaConnector');
const logger = require('firebase-functions/logger');

admin.initializeApp();
const db = admin.firestore();

const app = express();

// Set EJS as the view engine and specify the views directory
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- SmartThings Schema App (Existing Logic) ---
const smartthingsClientId = process.env.ST_CLIENT_ID_V2;
const smartthingsClientSecret = process.env.ST_CLIENT_SECRET_V2;

logger.info(`SmartApp Init - Client ID: ${smartthingsClientId ? smartthingsClientId.substring(0, 8) + '...' : 'NOT SET'}`);
logger.info(`SmartApp Init - Client Secret: ${smartthingsClientSecret ? smartthingsClientSecret.substring(0, 8) + '...' : 'NOT SET'}`);

const DEVICE_HANDLER_TYPE = 'af75a67e-896e-4ba5-ab02-3e3f2a115a8c';  // <- from your Developer Console

const connector = new SchemaConnector();

// ✅ 1. Discovery Handler
connector.discoveryHandler((accessToken, response) => {
    response.addDevice(
        'battery-alarm-001',              // externalDeviceId
        DEVICE_HANDLER_TYPE,              // deviceHandlerType: must match Developer Workspace
        'Battery Alarm Switch',           // Display name
        'Triggers SmartThings virtual device' // Description
    );
});

// ✅ 2. State Refresh Handler
connector.stateRefreshHandler(async (accessToken, response, devices) => {
    for (const device of devices) {
        if (device.deviceHandlerType === DEVICE_HANDLER_TYPE) {
            try {
                const deviceDoc = await db.collection('devices').doc(device.externalDeviceId).get();
                const currentState = deviceDoc.exists ? deviceDoc.data().state : 'off';

                response.addDeviceState(device.externalDeviceId, {
                    switch: { value: currentState }
                });
            } catch (error) {
                console.error(`Error fetching state for device ${device.externalDeviceId}:`, error);
            }
        }
    }
});

// ✅ 3. Command Handler - must be async to use await
connector.commandHandler(async (accessToken, response, devices) => {
    for (const device of devices) {
        try {
            if (device.deviceHandlerType === DEVICE_HANDLER_TYPE) {
                const command = device.commands[0];
                const value = command.command === 'on' ? 'on' : 'off';

                // ✅ Optional: fetch from Firestore
                const deviceDoc = await db.collection('devices')
                    .doc(device.externalDeviceId)
                    .get();

                // Log Firestore data (if exists)
                if (deviceDoc.exists) {
                    console.log(`Device ${device.externalDeviceId} data:`, deviceDoc.data());
                }

                // Respond with device state
                response.addDeviceState(device.externalDeviceId, {
                    switch: { value }
                });

                console.log(`Processed command: ${command.command} for device ${device.externalDeviceId}`);
            }
        } catch (err) {
            console.error(`Error handling command for ${device.externalDeviceId}:`, err);
        }
    }
});


// --- NEW: Firestore reference for user usage tracking ---
const userUsageRef = db.collection('userUsage');

// Helper function to get current month/year string for usage tracking
const getCurrentMonthYear = () => {
    const now = new Date();
    return `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}`;
};

// Helper function to get raw body from request stream
const getRawBody = (req) => {
    return new Promise((resolve, reject) => {
        let body = Buffer.alloc(0);
        req.on('data', (chunk) => {
            body = Buffer.concat([body, chunk]);
        });
        req.on('end', () => {
            resolve(body);
        });
        req.on('error', (error) => {
            reject(error);
        });
    });
};

// --- Middleware to verify access token and apply rate limiting ---
const verifyAccessTokenAndRateLimit = async (req, res, next) => {
    logger.info('✅ Middleware invoked: verifyAccessTokenAndRateLimit');
    const authHeader = req.headers.authorization;

    // Handle SmartThings schema requests without bearer tokens (e.g., discoveryRequest or ping)
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        const rawBody = await getRawBody(req);
        req.rawBody = rawBody;

        let interactionType = null;
        try {
            req.body = JSON.parse(rawBody.toString());
            interactionType = req.body?.headers?.interactionType;
        } catch (error) {
            logger.warn('❗ Could not parse body as JSON in unauthenticated request:', error);
            return res.status(400).json({ error: 'invalid_request', message: 'Invalid JSON format.' });
        }

        logger.info(`📡 Detected SmartThings schema call: interactionType=${interactionType}`);

        if (interactionType === 'discoveryRequest' || interactionType === 'ping') {
            logger.info(`✅ Allowed unauthenticated SmartThings interaction: ${interactionType}`);
            return next();
        }

        logger.warn('❌ Missing/invalid Authorization header in non-schema request');
        return res.status(401).json({ error: 'unauthorized', message: 'Bearer token required.' });
    }

    // Authenticated requests (e.g., stateRefresh, command, etc.)
    const accessToken = authHeader.split(' ')[1];

    try {
        const accessTokenDoc = await accessTokensRef.doc(accessToken).get();
        if (!accessTokenDoc.exists || accessTokenDoc.data().expires_at < Date.now()) {
            logger.warn('❌ Invalid or expired access token.');
            return res.status(401).json({ error: 'unauthorized', message: 'Invalid or expired access token.' });
        }

        const userId = accessTokenDoc.data().user_id;
        if (!userId) {
            logger.warn('❌ Access token missing user ID.');
            return res.status(401).json({ error: 'unauthorized', message: 'Token missing user ID.' });
        }

        req.userId = userId;

        const monthYear = getCurrentMonthYear();
        const userUsageDocRef = userUsageRef.doc(userId);
        let rateLimitExceeded = false;

        await db.runTransaction(async (transaction) => {
            const doc = await transaction.get(userUsageDocRef);
            let count = 0;
            let usageData = {};

            if (doc.exists) {
                usageData = doc.data();
                count = usageData[monthYear]?.count || 0;
            }

            const MAX = 100;
            if (count >= MAX) {
                logger.warn(`⛔ Rate limit exceeded for user ${userId} (${count}/${MAX})`);
                rateLimitExceeded = true;
                return;
            }

            const newCount = count + 1;
            usageData[monthYear] = {
                count: newCount,
                lastInvocation: admin.firestore.FieldValue.serverTimestamp()
            };
            transaction.set(userUsageDocRef, usageData, { merge: true });

            logger.info(`📊 Updated usage for ${userId}: ${newCount}`);
        });

        if (rateLimitExceeded) {
            return res.status(429).json({
                statusCode: 429,
                error: {
                    type: 'RATE_LIMIT_EXCEEDED',
                    message: `Rate limit exceeded (${MAX} requests per month).`
                }
            });
        }

        return next();

    } catch (error) {
        logger.error('💥 Middleware error:', error);
        return res.status(500).json({ error: 'server_error', message: 'Internal error during request authentication.' });
    }
};


// The main SmartThings Schema endpoint (handles lifecycle events like page, updated, subscribedEventHandler)
// It needs the raw body for signature verification.
app.post('/smartthings', verifyAccessTokenAndRateLimit, async (req, res) => {
    logger.info(`📥 SmartThings request body received at /smartthings: ${JSON.stringify(req.body)}`);
    try {
        await connector.handleHttpCallback(req, res);  // ✅ CORRECT
    } catch (error) {
        logger.error('SmartApp handler error:', error);
        res.status(500).send('Internal Server Error');
    }
});


// --- NEW: Add a POST route for the root path to handle SmartThings Schema requests ---
// SmartThings might POST to the root path after OAuth completion. It also needs raw body.
app.post('/', verifyAccessTokenAndRateLimit, async(req, res) => {
    logger.info('Incoming SmartThings Schema request received at root path (after rate limit check).');
     try {
    await connector.handleHttpCallback(req, res);  // ✅ CORRECT
  } catch (error) {
    logger.error('SmartApp handler error (root):', error);
    res.status(500).send('Internal Server Error');
  }
});


// --- OAuth 2.0 Authorization Server (Existing Logic) ---
// These endpoints DO need body-parser, so apply it specifically to them.
app.use('/oauth', bodyParser.urlencoded({ extended: true })); // For /oauth/login POST
app.use('/oauth', bodyParser.json()); // For /oauth/token POST

const oauthClientsRef = db.collection('oauthClients');
const authCodesRef = db.collection('authCodes');
const accessTokensRef = db.collection('accessTokens');
const refreshTokensRef = db.collection('refreshTokens');

const generateRandomString = (length) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
};

app.get('/oauth/authorize', async (req, res) => {
    logger.info('OAuth /authorize request received.');
    const { client_id, response_type, redirect_uri, scope, state } = req.query;

    if (!client_id || !response_type || !redirect_uri || response_type !== 'code') {
        logger.warn('Invalid OAuth parameters in /oauth/authorize request.');
        return res.status(400).send('Invalid OAuth parameters.');
    }

    try {
        const clientDoc = await oauthClientsRef.doc(client_id).get();
        if (!clientDoc.exists) {
            logger.warn(`OAuth client ${client_id} not found during authorization.`);
            return res.status(401).json({ error: 'invalid_client' });
        }
        const client = clientDoc.data();

        if (!client.redirect_uris || !client.redirect_uris.includes(redirect_uri)) {
            logger.warn(`Invalid redirect_uri: ${redirect_uri} for client ${client_id}.`);
            return res.status(400).json({ error: 'invalid_redirect_uri' });
        }

        res.render('login', { client_id, redirect_uri, scope, state, error: null });

    } catch (error) {
        logger.error('Error in /oauth/authorize endpoint:', error);
        res.status(500).json({ error: 'server_error' });
    }
});

app.post('/oauth/login', async (req, res) => {
    logger.info('OAuth /login POST request received.');
    const { email, password, client_id, redirect_uri, scope, state } = req.body;

    try {
        const userRecord = await admin.auth().getUserByEmail(email);

        if (!userRecord) {
            logger.warn(`Login failed for email: ${email} - User not found.`);
            return res.render('login', { client_id, redirect_uri, scope, state, error: 'Invalid credentials.' });
        }

        const authCode = generateRandomString(32);
        const expiresAt = Date.now() + 5 * 60 * 1000;

        await authCodesRef.doc(authCode).set({
            client_id,
            user_id: userRecord.uid,
            redirect_uri,
            scope,
            expires_at: expiresAt,
        });

        const redirectUrl = `${redirect_uri}?code=${authCode}&state=${state}`;
        logger.info(`Redirecting to SmartThings with authorization code: ${redirectUrl}`);
        res.redirect(redirectUrl);

    } catch (error) {
        logger.error('Error during OAuth login POST:', error);
        if (error.code === 'auth/user-not-found') {
            return res.render('login', { client_id, redirect_uri, scope, state, error: 'User not found.' });
        }
        res.status(500).json({ error: 'server_error' });
    }
});

app.post('/oauth/token', async (req, res) => {
    logger.info('OAuth /token request received.');
    const {
    grant_type,
    code,
    refresh_token,
    client_id,
    client_secret,
    redirect_uri
} = req.body;

if (!client_id || !client_secret) {
    return res.status(400).json({ error: 'invalid_request', message: 'Missing client_id or client_secret' });
}

const clientDoc = await oauthClientsRef.doc(client_id).get();
if (!clientDoc.exists) {
    return res.status(401).json({ error: 'invalid_client' });
}

const client = clientDoc.data();
if (client.client_secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
}

if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri) {
        return res.status(400).json({ error: 'invalid_request', message: 'Missing code or redirect_uri' });
    }

    const authCodeDoc = await authCodesRef.doc(code).get();
    if (!authCodeDoc.exists) {
        return res.status(400).json({ error: 'invalid_grant' });
    }

    const authCodeData = authCodeDoc.data();

    if (
        authCodeData.client_id !== client_id ||
        authCodeData.redirect_uri !== redirect_uri ||
        authCodeData.expires_at < Date.now()
    ) {
        return res.status(400).json({ error: 'invalid_grant' });
    }

    await authCodesRef.doc(code).delete();

    const accessToken = generateRandomString(64);
    const refreshToken = generateRandomString(64);
    const expiresIn = 3600;

    await accessTokensRef.doc(accessToken).set({
        client_id,
        user_id: authCodeData.user_id,
        scope: authCodeData.scope,
        expires_at: Date.now() + expiresIn * 1000,
    });

    await refreshTokensRef.doc(refreshToken).set({
        client_id,
        user_id: authCodeData.user_id,
        scope: authCodeData.scope,
    });

    return res.json({
        access_token: accessToken,
        token_type: 'bearer',
        expires_in: expiresIn,
        refresh_token: refreshToken,
        scope: authCodeData.scope,
    });

} else if (grant_type === 'refresh_token') {
    if (!refresh_token) {
        return res.status(400).json({ error: 'invalid_request', message: 'Missing refresh_token' });
    }

    const refreshDoc = await refreshTokensRef.doc(refresh_token).get();
    if (!refreshDoc.exists) {
        return res.status(400).json({ error: 'invalid_grant', message: 'Invalid refresh token' });
    }

    const refreshData = refreshDoc.data();

    const accessToken = generateRandomString(64);
    const expiresIn = 3600;

    await accessTokensRef.doc(accessToken).set({
        client_id,
        user_id: refreshData.user_id,
        scope: refreshData.scope,
        expires_at: Date.now() + expiresIn * 1000,
    });

    return res.json({
        access_token: accessToken,
        token_type: 'bearer',
        expires_in: expiresIn,
        scope: refreshData.scope,
    });

} else {
    logger.warn(`Unsupported grant_type: ${grant_type}`);
    return res.status(400).json({ error: 'unsupported_grant_type' });
}

    if (!code || !client_id || !client_secret || !redirect_uri) {
        logger.warn('Missing required parameters in token request.');
        return res.status(400).json({ error: 'invalid_request' });
    }

    try {
        const clientDoc = await oauthClientsRef.doc(client_id).get();
        if (!clientDoc.exists) {
            logger.warn(`Token request: OAuth client ${client_id} not found.`);
            return res.status(401).json({ error: 'invalid_client' });
        }
        const client = clientDoc.data();

        if (client.client_secret !== client_secret) {
            logger.warn(`Token request: Invalid client secret for ${client_id}.`);
            return res.status(401).json({ error: 'invalid_client' });
        }

        const authCodeDoc = await authCodesRef.doc(code).get();
        if (!authCodeDoc.exists) {
            logger.warn(`Token request: Invalid authorization code: ${code}.`);
            return res.status(400).json({ error: 'invalid_grant' });
        }
        const authCodeData = authCodeDoc.data();

        if (authCodeData.client_id !== client_id || authCodeData.redirect_uri !== redirect_uri || authCodeData.expires_at < Date.now()) {
            logger.warn(`Token request: Authorization code validation failed for code ${code}.`);
            return res.status(400).json({ error: 'invalid_grant' });
        }

        await authCodesRef.doc(code).delete();

        const accessToken = generateRandomString(64);
        const refreshToken = generateRandomString(64);
        const expiresIn = 3600;

        await accessTokensRef.doc(accessToken).set({
            client_id,
            user_id: authCodeData.user_id,
            scope: authCodeData.scope,
            expires_at: Date.now() + expiresIn * 1000,
        });

        await refreshTokensRef.doc(refreshToken).set({
            client_id,
            user_id: authCodeData.user_id,
            scope: authCodeData.scope,
        });

        logger.info(`Tokens issued for client ${client_id}, user ${authCodeData.user_id}.`);
        res.json({
            access_token: accessToken,
            token_type: 'bearer',
            expires_in: expiresIn,
            refresh_token: refreshToken,
            scope: authCodeData.scope,
        });

    } catch (error) {
        logger.error('Error in /oauth/token endpoint:', error);
        res.status(500).json({ error: 'server_error' });
    }
});

console.log("✅ Exporting smartthingsConnector");
// Export the Express app as a single Firebase Function
exports.smartthingsConnector = onHttpRequest({ region: 'us-central1' }, app);
