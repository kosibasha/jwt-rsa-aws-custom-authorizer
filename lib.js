require('dotenv').config({ silent: true });

const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');
const util = require('util');

// Extract and return the Bearer Token from the Lambda event parameters
const getToken = (params) => {
    if (!params.type || params.type !== 'REQUEST') {
        throw new Error('Expected "event.type" parameter to have value "REQUEST"');
    }

    const tokenString = params.headers.authorization;
    if (!tokenString) {
        throw new Error('Expected "event.headers.authorization" parameter to be set');
    }

    const match = tokenString.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) {
        throw new Error(`Invalid Authorization token - ${tokenString} does not match "Bearer .*"`);
    }
    return match[1];
};

const jwtOptions = {
    audience: process.env.AUDIENCE,
    issuer: process.env.TOKEN_ISSUER,
};

module.exports.authenticate = async (params) => {
    console.log('Authenticating request:', params);

    const token = getToken(params);

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header || !decoded.header.kid) {
        throw new Error('Invalid token');
    }

    const sub = decoded.payload.sub;
    console.log('User ID (sub claim):', sub);

    const getSigningKey = util.promisify(client.getSigningKey);
    try {
        const key = await getSigningKey(decoded.header.kid);
        const signingKey = key.publicKey || key.rsaPublicKey;

        jwt.verify(token, signingKey, jwtOptions);
        console.log('Token is valid for:', sub);

        // Determine response based on the "sub" claim
        const context = {};  // Initialize the context object

        if (sub.endsWith('@clients')) {
            // Set clientId in the context if sub ends with '@clients'
            context.clientId = sub.replace('@clients', ''); // Remove '@clients' for clarity
        } else {
            // Set userId in the context if sub doesn't end with '@clients'
            context.userId = sub;
        }

        // Return the authorization response with context
        return {
            isAuthorized: true,
            context: context,  // Pass the context with the clientId or userId
        };
    } catch (error) {
        console.error('Token verification failed:', error.message);
        throw new Error('Unauthorized');
    }
};


const client = jwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10, // Default value
    jwksUri: process.env.JWKS_URI,
});
