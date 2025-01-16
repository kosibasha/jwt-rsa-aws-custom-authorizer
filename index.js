const lib = require('./lib');

// Lambda function handler
module.exports.handler = async (event, context) => {
    let response = {
        "isAuthorized": false,
    };

    try {
        // Validate token and get response from lib
        const authResponse = await lib.authenticate(event);

        // Update the response with authorization details
        console.log('Authorization successful:', authResponse);
        response = authResponse;
    } catch (err) {
        console.log('Unauthorized:', err.message);
        context.fail('Unauthorized');
    }

    // Return the final response
    return response;
};
