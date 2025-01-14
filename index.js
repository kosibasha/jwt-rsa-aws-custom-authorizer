const lib = require('./lib');

// Lambda function handler
module.exports.handler = async (event, context, callback) => {
    let response = {
        "isAuthorized": false
    };

    try {
        // Validate token with your authentication logic
        await lib.authenticate(event);

        // If token is valid, update the response
        console.log("allowed");
        response = {
            "isAuthorized": true
        };
    }
    catch (err) {
        console.log("Unauthorized", err);
        context.fail("Unauthorized");
    }

    // Return the final response
    return response;
};
