// --- Import Firebase Functions v2 for HTTP triggers ---
const { onRequest } = require('firebase-functions/v2/https');
const { setGlobalOptions } = require('firebase-functions/v2');
const { logger } = require('firebase-functions');

// --- Import other necessary modules ---
const admin = require('firebase-admin');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const { SchemaConnector } = require('st-schema'); // CORRECT: Using st-schema SDK

admin.initializeApp();
const db = admin.firestore();

setGlobalOptions({
    region: 'us-central1',
    memory: '256Mi',
    timeoutSeconds: 60
});

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- SmartThings Schema App (Core Logic) ---
const smartthingsClientId = process.env.ST_CLIENT_ID_V2; // Still used for logging/context if needed
const smartthingsClientSecret = process.env.ST_CLIENT_SECRET_V2; // Still used for logging/context if needed

logger.info(`SmartApp Init - Client ID: ${smartthingsClientId ? smartthingsClientId.substring(0, 8) + '...' : 'NOT SET'}`);
logger.info(`SmartApp Init - Client Secret: ${smartthingsClientSecret ? smartthingsClientSecret.substring(0, 8) + '...' : 'NOT SET'}`);

// --- FIX START: Initialize SchemaConnector and define handlers ---
const connector = new SchemaConnector()
    .enableEventLogging(2) // Enable event logging for debugging
    .discoveryHandler((accessToken, response) => {
        logger.info('Handling st-schema discovery request.');
        // Use response.addDevice as per st-schema documentation
        // deviceHandlerType must match what's configured in Developer Workspace if not using profileId

        try {
            //const deviceId = 'battery-alarm-switch-1';
            //const deviceType = 'c2c-switch';
            //const deviceName = 'Battery Alarm Switch';

            //logger.info(`Adding device to response: ${deviceId}, type: ${deviceType}, name: ${deviceName}`);

          //  const device = {
           //    externalDeviceId: 'battery-alarm-switch-1',
           //     deviceHandlerType: 'c2c-switch',
           //     manufacturerName: 'Cool Coder',
           //     modelName: 'Virtual Switch 1.0',
           //     hwVersion: '1.0',
           //     swVersion: '1.0',
           //     deviceName: 'Battery Alarm Switch',
           //     roomName: 'Default Room',
           // };
          //  const device = {
          //      'battery-alarm-switch-1',
          //      deviceHandlerType: 'c2c-switch',
          //      manufacturerName: 'Cool Coder',
          //      modelName: 'Virtual Switch 1.0',
          //      hwVersion: '1.0',
          //      swVersion: '1.0',
          //      deviceName: 'Battery Alarm Switch',
          //      roomName: 'Default Room',
          //  };
            
          //  logger.info('Device object before addDevice:', JSON.stringify(device)); 
            response.addDevice({
               externalDeviceId: 'battery-alarm-switch-1',
               friendlyName: 'Battery Alarm Switch',
               manufacturerInfo: {
               manufacturerName: 'Cool Coder',
               modelName: 'Virtual Switch 1.0',
               hwVersion: '1.0',
               swVersion: '1.0'
               },
              deviceHandlerType: 'c2c-switch'
             });
        //    response.send();

            logger.info('st-schema Discovery response sent.');
        } catch (error) {
            logger.error('Error in discovery handler:', error);
        }
    })
    .stateRefreshHandler(async (accessToken, response, devices) => {
        logger.info('Handling st-schema state refresh request.');
        for (const device of devices) {
            if (device.deviceHandlerType === 'c2c-switch') {
                try {
                    // Fetch current state from your backend (e.g., Firestore)
                    // For now, return a default state
                    const currentState = 'off'; // Replace with actual state from your app
                    const currentBattery = 100; // Replace with actual battery from your app

                    const component = response.addDevice(device.externalDeviceId).addComponent('main');
                    component.addState('st.switch', 'switch', currentState);
                    component.addState('st.battery', 'battery', currentBattery);
                    component.addState('st.healthCheck', 'healthStatus', 'online');
                } catch (error) {
                    logger.error(`Error fetching state for device ${device.externalDeviceId}:`, error);
                }
            }
        }
        logger.info('st-schema State refresh response sent.');
    })
    .commandHandler(async (accessToken, response, devices) => {
        logger.info('Handling st-schema command request.');
        for (const device of devices) {
            if (device.deviceHandlerType === 'c2c-switch') {
                const component = response.addDevice(device.externalDeviceId).addComponent('main');
                for (const command of device.commands) {
                    logger.info(`Received command: ${command.capability} - ${command.command} for device ${device.externalDeviceId}`);
                    switch (command.capability) {
                        case 'st.switch':
                            const switchValue = command.command === 'on' ? 'on' : 'off';
                            // TODO: Implement logic to send command to your Android app (e.g., via FCM)
                            component.addState('st.switch', 'switch', switchValue);
                            break;
                        // Add other capabilities if needed (e.g., for battery level setting, though usually reported)
                    }
                }
            }
        }
        logger.info('st-schema Command response sent.');
    })
    .callbackAccessHandler(async (accessToken, callbackAuthentication, callbackUrls) => {
        logger.info('Handling st-schema callbackAccessHandler (OAuth tokens).');
        // This handler is crucial for st-schema to store the access tokens
        // received from your OAuth server. You need to store these tokens
        // securely in your database (e.g., Firestore) linked to the user.
        // The accessToken here is the one issued by YOUR /oauth/token endpoint.
        // callbackAuthentication contains client_id, client_secret, etc.
        // callbackUrls contains the URLs SmartThings will use to send events to your connector.

        logger.info(`Access Token from OAuth: ${accessToken ? accessToken.substring(0, 8) + '...' : 'N/A'}`);
        logger.info(`Callback Authentication: ${JSON.stringify(callbackAuthentication)}`);
        logger.info(`Callback URLs: ${JSON.stringify(callbackUrls)}`);

        // --- FIX START: Implement secure storage of accessToken, callbackAuthentication, callbackUrls ---
        if (accessToken && callbackAuthentication && callbackAuthentication.client_id) {
            try {
                // You need to get the user ID associated with this accessToken.
                // This usually means verifying the accessToken with your own OAuth server (this function).
                // For simplicity here, we'll assume the user ID can be derived from the accessTokenDoc if it exists
                // OR that callbackAuthentication.principal is the user ID.
                // For now, let's look up the user ID from our accessTokens collection.
                const accessTokenDoc = await accessTokensRef.doc(accessToken).get();
                let userId = null;
                if (accessTokenDoc.exists) {
                    userId = accessTokenDoc.data().user_id;
                } else {
                    logger.warn('CallbackAccessHandler: Access token not found in our database. Cannot link to user.');
                    // In a real app, you might try to verify the token with SmartThings or your own auth server.
                    // For this example, we'll proceed without a linked userId if not found.
                }

                if (userId) {
                    await db.collection('smartthingsInstalls').doc(userId).set({
                        userId: userId, // Your internal user ID
                        stAccessToken: accessToken,
                        stRefreshToken: callbackAuthentication.refreshToken || null, // Refresh token from SmartThings
                        stCallbackUrls: callbackUrls, // URLs for sending proactive events
                        clientId: callbackAuthentication.client_id, // SmartThings' client ID for your OAuth server
                        timestamp: admin.firestore.FieldValue.serverTimestamp()
                    }, { merge: true });
                    logger.info(`SmartThings tokens stored for user ${userId}.`);
                } else {
                    logger.warn('SmartThings tokens not stored: User ID could not be determined from access token.');
                }
            } catch (error) {
                logger.error('Failed to store SmartThings tokens in callbackAccessHandler:', error);
            }
        } else {
            logger.warn('CallbackAccessHandler: Missing accessToken or callbackAuthentication.client_id.');
        }
        // --- FIX END ---
    })
    .integrationDeletedHandler(async (accessToken) => {
        logger.info('Handling st-schema integrationDeletedHandler.');
        // TODO: Clean up user data and tokens from your database when integration is removed from SmartThings
        logger.info(`Integration deleted for access token: ${accessToken ? accessToken.substring(0, 8) + '...' : 'N/A'}`);
    });
// --- FIX END ---


// --- Firestore reference for user usage tracking ---
const userUsageRef = db.collection('userUsage');
const oauthClientsRef = db.collection('oauthClients');
const authCodesRef = db.collection('authCodes');
const accessTokensRef = db.collection('accessTokens');
const refreshTokensRef = db.collection('refreshTokens');


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
        req.on('error', (err) => {
            reject(err);
        });
    });
};

// --- Middleware to verify access token and apply rate limiting ---
const verifyAccessTokenAndRateLimit = async (req, res, next) => {
    logger.info('Executing verifyAccessTokenAndRateLimit middleware.');
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        const rawBody = await getRawBody(req);
        let interactionType = null;
        try {
            const parsedBody = JSON.parse(rawBody.toString());
            interactionType = parsedBody?.headers?.interactionType;
        } catch (e) {
            logger.warn('Could not parse raw body for interactionType during unauthenticated check (this is normal for non-Schema requests or initial connection):', e);
        }

        if (interactionType === 'discoveryRequest' || interactionType === 'ping') {
            logger.info(`Unauthenticated Schema request (${interactionType}) detected, skipping Bearer token check.`);
            req.rawBody = rawBody;
            try {
                req.body = JSON.parse(rawBody.toString());
            } catch (err) {
                logger.error('Failed to parse body for SmartApp schema request after raw body read:', err);
                return res.status(400).json({ error: 'invalid_request', message: 'Could not parse body as JSON.' });
            }
            return next();
        }
        logger.warn('Missing or invalid Authorization header in non-Schema request or unknown Schema type.');
        return res.status(401).json({ error: 'unauthorized', message: 'Bearer token required for this request type.' });
    }

    const accessToken = authHeader.split(' ')[1];

    try {
        const accessTokenDoc = await accessTokensRef.doc(accessToken).get();
        if (!accessTokenDoc.exists || accessTokenDoc.data().expires_at < Date.now()) {
            logger.warn('Invalid or expired access token in Schema request.');
            return res.status(401).json({ error: 'unauthorized', message: 'Invalid or expired access token.' });
        }

        const userId = accessTokenDoc.data().user_id;
        if (!userId) {
            logger.warn('Access token does not contain user ID.');
            return res.status(401).json({ error: 'unauthorized', message: 'Invalid access token data.' });
        }

        req.userId = userId;

        const monthYear = getCurrentMonthYear();
        const userUsageDocRef = userUsageRef.doc(userId);

        let rateLimitExceeded = false;
        await db.runTransaction(async (transaction) => {
            const userUsageDoc = await transaction.get(userUsageDocRef);
            let currentCount = 0;
            let usageData = {};

            if (userUsageDoc.exists) {
                usageData = userUsageDoc.data();
                if (usageData[monthYear]) {
                    currentCount = usageData[monthYear].count || 0;
                }
            }

            const MAX_INVOCATIONS_PER_MONTH = 100;

            if (currentCount >= MAX_INVOCATIONS_PER_MONTH) {
                rateLimitExceeded = true;
                logger.warn(`Rate limit exceeded for user ${userId} in ${monthYear}. Count: ${currentCount}`);
                return;
            }

            const newCount = currentCount + 1;
            usageData[monthYear] = {
                count: newCount,
                lastInvocation: admin.firestore.FieldValue.serverTimestamp()
            };
            transaction.set(userUsageDocRef, usageData, { merge: true });

            logger.info(`User ${userId} invocation count for ${monthYear}: ${newCount}`);
        });

        if (rateLimitExceeded) {
            return res.status(429).json({
                headers: {},
                statusCode: 429,
                error: {
                    message: `Rate limit of ${MAX_INVOCATIONS_PER_MONTH} invocations per month exceeded.`,
                    type: 'RATE_LIMIT_EXCEEDED'
                }
            });
        }
        next();

    } catch (error) {
        logger.error('Error in verifyAccessTokenAndRateLimit middleware:', error);
        res.status(500).json({ error: 'server_error', message: 'Internal authentication error.' });
    }
};


// The main SmartThings Schema endpoint (handles lifecycle events like page, updated, subscribedEventHandler)
// It needs the raw body for signature verification.
app.post('/smartthings', verifyAccessTokenAndRateLimit, async (req, res) => {
    logger.info(`📥 SmartThings request body received at /smartthings: ${JSON.stringify(req.body)}`);
    try {
        await connector.handleHttpCallback(req, res); // Call connector.handleHttpCallback for st-schema SDK
    } catch (error) {
        logger.error('SmartApp handler error:', error);
        res.status(500).send('Internal Server Error');
    }
});


// --- NEW: Add a POST route for the root path to handle SmartThings Schema requests ---
// SmartThings might POST to the root path after OAuth completion. It also needs raw body.
    app.use(bodyParser.raw({ type: '*/*' }));
    app.post('/', async (req, res) => {
    logger.info('Incoming SmartThings Schema request received at root path after rate limit check');
    logger.info('🔁 Received POST / from SmartThings');
    logger.info('📦 Request Body: ' + JSON.stringify(req.body));
    try {
        await connector.handleHttpCallback(req, res); // Call connector.handleHttpCallback for st-schema SDK
    } catch (error) {
        logger.error('SmartApp handler error (root):', error);
        res.status(500).send('Internal Server Error');
    }
});

// --- FIX START: Add GET routes for basic endpoint verification ---
// SmartThings might send GET requests for initial endpoint verification.
app.get('/smartthings', (req, res) => {
    logger.info('Received GET request to /smartthings. Responding with 200 OK.');
    res.status(200).send('SmartThings Schema Endpoint is alive.');
});

app.get('/', (req, res) => {
    logger.info('Received GET request to root path. Responding with 200 OK.');
    res.status(200).send('SmartThings Schema Endpoint is alive.');
});
// --- FIX END ---


// --- OAuth 2.0 Authorization Server (Existing Logic) ---
// These endpoints DO need body-parser, so apply it specifically to them.
app.use('/oauth', bodyParser.urlencoded({ extended: true })); // For /oauth/login POST
app.use('/oauth', bodyParser.json()); // For /oauth/token POST

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
            return res.status(500).json({ error: 'server_error' });
        }
        res.status(500).json({ error: 'server_error' });
    }
});

app.post('/oauth/token', async (req, res) => {
    logger.info('OAuth /token request received.');
    const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;

    if (grant_type !== 'authorization_code') {
        logger.warn(`Invalid grant_type: ${grant_type} in token request.`);
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

// Export the Express app as a single Firebase Function
exports.smartthingsConnector = onRequest(app);
