const Joi = require('joi');
const bcrypt = require('bcrypt');
const _ = require('lodash');
const winston = require('winston');
const express = require('express');
const router = express.Router();
const dotenv = require('dotenv');
const AWS = require('aws-sdk');
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const jwt_decode = require('jwt-decode');
const jwt = require('jsonwebtoken');
const { createUser, getUsers, getUserByEmail, updateUser, deleteUser, getUserByUsername, updatePassword, updateUserConfirmation } = require('../models/user');

dotenv.config();


const UserPoolId = process.env.AWS_COGNITO_USER_POOL_ID;
const ClientId = process.env.AWS_COGNITO_CLIENT_ID;
const Region = process.env.AWS_COGNITO_REGION;



AWS.config.update({ region: Region }); // Replace with your AWS region


const poolData = {
    UserPoolId,
    ClientId
}


router.post('/login', async (req, res) => {
    const { userid, username, password } = req.body;

    if (userid) {
        console.log("validateLoginWithID");
        const { error } = validateLoginWithID(req.body);
        if (error) return res.status(400).json({ message: 'Validation Error', error: error.details[0].message });
    } else {
        console.log("validateLogin");
        const { error } = validateLogin(req.body);
        if (error) return res.status(400).json({ message: 'Validation Error', error: error.details[0].message });
    }



    let user = await getUserByUsername(username);
    if (!user) return res.status(400).json({ message: 'Username not exist', error: "Username not exist" });

    if (userid) {
        if (user.contractornumber != userid) return res.status(400).json({ message: 'User ID is incorrect', error: "User ID is incorrect" });
    }

    if (!user.isconfirm) return res.status(400).json({ message: 'User is nor confirmed prior authentication', error: "User is nor confirmed prior authentication" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid Password', error: "Invalid Password" });


    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
        Username: username,
        Password: password,
    });

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
        Username: username,
        Pool: userPool,
    });

    try {

        const authResult = await new Promise((resolve, reject) => {
            cognitoUser.authenticateUser(authenticationDetails, {
                onSuccess: (data) => resolve(data),
                onFailure: (err) => reject(err),
                // onSuccess: (result) => {
                //     // Successful login
                //     console.log('Access Token: ' + result.getAccessToken().getJwtToken());
                //     res.json({
                //         message: 'Login successful',
                //         accessToken: result.getAccessToken().getJwtToken(),
                //     });
                // },
                // onFailure: (err) => {
                //     // If authentication failed
                //     console.error(err);
                //     res.status(401).json({ message: 'Authentication failed', error: err });
                // },
                // mfaRequired: (challengeName, challengeParameters) => {
                //     // Handle MFA challenge
                //     console.log('MFA required: ', challengeName);

                //     if (challengeName === 'SMS_MFA' || challengeName === 'SOFTWARE_TOKEN_MFA') {
                //         res.status(403).json({
                //             message: 'MFA required',
                //             challengeName,
                //             challengeParameters,
                //         });
                //     }
                // },
            });
        });

        const accessToken = authResult.getAccessToken().getJwtToken();
        const idToken = authResult.getIdToken().getJwtToken();
        const refreshToken = authResult.getRefreshToken().getToken();

        winston.info(authResult);
        res.status(200).json({
            message: 'Login successful',
            accessToken: accessToken,
            idToken: idToken,
            refreshToken: refreshToken
        });
    } catch (error) {
        winston.error('Error login user:', error);
        res.status(400).json({ message: 'Login failed', error: error.message });
    }
});



router.post('/signup', async (req, res) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).json({ message: 'Validation Error', error: error.details[0].message });

    // const { username, name, given_name, family_name, phone_number, email, password } = req.body;
    const { username, given_name, family_name, phone_number, email, password } = req.body;

    let user = await getUserByEmail(email);
    if (user) return res.status(400).json({ message: 'Invalid email or password', error: "Invalid email or password" });

    const salt = await bcrypt.genSalt(15);
    const hashedPassword = await bcrypt.hash(password, salt);

    try {

        const attributeList = [
            new AmazonCognitoIdentity.CognitoUserAttribute({
                Name: 'email',
                Value: email
            })
        ];

        attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({
            Name: "phone_number",
            Value: phone_number
        }));

        attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({
            Name: "given_name",
            Value: given_name
        }));

        attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({
            Name: "family_name",
            Value: family_name
        }));

        const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

        const aws_result = await new Promise((resolve, reject) => {
            userPool.signUp(username, password, attributeList, null, (err, data) => {
                if (err) reject(err);
                resolve(data);
            });
        });


        const name = given_name + " " + family_name;
        const isConfirm = false;
        const contractor_number = Math.floor(Date.now() / 1000);

        const result = await createUser(name, email, hashedPassword, username, isConfirm, contractor_number);
        winston.info('User created successfully:', result.rows[0]);
        res.status(201).send(_.pick(result.rows[0], ['id', 'name', 'email', 'username']));



    } catch (err) {
        winston.error('Error creating user:', err);
        // res.status(400).send(err);
        res.status(400).json({ message: 'Sign-up Error!', data: err });
    }

});


router.post('/confirm', async (req, res) => {
    const { username, confirmationCode } = req.body;

    const { error } = validateConfirmationCode(req.body);
    if (error) return res.status(400).json({ message: 'Validation Error', error: error.details[0].message });


    let user = await getUserByUsername(username);
    if (!user) return res.status(400).json({ message: 'Username not exist!', error: "Username not exist!" });


    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
        Username: username,
        Pool: userPool,
    });

    try {
        const result = await new Promise((resolve, reject) => {
            cognitoUser.confirmRegistration(confirmationCode, true, (err, data) => {
                if (err) reject(err);
                resolve(data);
            });
        });

        const isConfirm = true;

        const dbResult = await updateUserConfirmation(user.id, isConfirm);
        winston.info('User changed isConfirm value successfully:', dbResult);

        res.status(200).json({ message: 'User confirmed successfully', data: result });
    } catch (error) {
        winston.error('Error confirming registration:', error);
        res.status(400).json({ message: 'Error confirming registration', error: error.message });
    }
});



router.post('/resend-confirmation-code', async (req, res) => {
    const { username } = req.body;

    const { error } = validateUsername(req.body);
    if (error) return res.status(400).json({ message: 'Validation Error', error: error.details[0].message });


    let user = await getUserByUsername(username);
    if (!user) return res.status(400).json({ message: 'Username not exist!', error: "Username not exist!" });


    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
        Username: username,
        Pool: userPool,
    });

    try {
        const result = await new Promise((resolve, reject) => {
            cognitoUser.resendConfirmationCode((err, data) => {
                if (err) reject(err);
                resolve(data);
            });
        });

        winston.info('User sent new code successfully:', result);

        res.status(200).json({ message: 'User sent new code', data: result });
    } catch (error) {
        winston.error('Error confirming registration:', error);
        res.status(400).json({ message: 'Error confirming registration', error: error.message });
    }
});



router.post('/refresh-token', async (req, res) => {
    const { refreshToken, username } = req.body;

    const { error } = validateUsernameAndToken(req.body);
    if (error) return res.status(400).json({ message: 'Validation Error', error: error.details[0].message });

    let user = await getUserByUsername(username);
    if (!user) return res.status(400).json({ message: 'Username not exist!', error: "Username not exist!" });


    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    const userData = {
        Username: username, // You need to pass the username
        Pool: userPool
    };

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    const refreshTokenObj = new AmazonCognitoIdentity.CognitoRefreshToken({
        RefreshToken: refreshToken
    });

    try {
        const result = await new Promise((resolve, reject) => {
            cognitoUser.refreshSession(refreshTokenObj, (err, session) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(session);
                }
            });
        });

        const newAccessToken = result.getAccessToken().getJwtToken();
        const newIdToken = result.getIdToken().getJwtToken();
        const newRefreshToken = result.getRefreshToken().getToken();

        res.status(200).json({
            accessToken: newAccessToken,
            idToken: newIdToken,
            refreshToken: newRefreshToken
        });
    } catch (err) {
        winston.error('Error during token refresh:', err);
        res.status(500).json({ message: 'Token refresh failed', error: err.message });
    }



});



// Logout user (clear the session)
router.post('/logout', async (req, res) => {
    const { username } = req.body;


    const { error } = validateUsername(req.body);
    if (error) return res.status(400).json({ message: 'Validation Error', error: error.details[0].message });

    let user = await getUserByUsername(username);
    if (!user) return res.status(400).json({ message: 'Username not exist!', error: "Username not exist!" });



    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
        Username: username,
        Pool: userPool,
    });

    try {
        cognitoUser.signOut();
        res.status(200).json({ message: 'User logged out successfully' });
    } catch (error) {
        res.status(400).json({ message: 'Error logging out', error: error.message });
    }
});




// Password Reset - Initiate Forgot Password Flow
router.post('/forgot-password', async (req, res) => {
    const { username } = req.body;

    const { error } = validateUsername(req.body);
    if (error) return res.status(400).json({ message: 'Validation Error', error: error.details[0].message });

    let user = await getUserByUsername(username);
    if (!user) return res.status(400).json({ message: 'Username not exist!', error: "Username not exist!" });


    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);


    const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
        Username: username,
        Pool: userPool,
    });

    try {
        const result = await new Promise((resolve, reject) => {
            cognitoUser.forgotPassword({
                onSuccess: (data) => resolve(data),
                onFailure: (err) => reject(err),
            });
        });
        res.status(200).json({ message: 'Password reset email sent', data: result });
    } catch (error) {
        res.status(400).json({ message: 'Error sending reset email', error: error.message });
    }
});


// Confirm Password Reset
router.post('/confirm-reset-password', async (req, res) => {
    const { username, confirmationCode, newPassword } = req.body;

    const { error } = validateConfirmReset(req.body);
    if (error) return res.status(400).json({ message: 'Validation Error', error: error.details[0].message });

    let user = await getUserByUsername(username);
    if (!user) return res.status(400).json({ message: 'Username not exist!', error: "Username not exist!" });


    const salt = await bcrypt.genSalt(15);
    const hashedPassword = await bcrypt.hash(newPassword, salt);


    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
        Username: username,
        Pool: userPool,
    });

    try {
        const result = await new Promise((resolve, reject) => {
            cognitoUser.confirmPassword(confirmationCode, newPassword, {
                onSuccess: (data) => resolve(data),
                onFailure: (err) => reject(err),
            });
        });

        const dbResult = await updatePassword(user.id, hashedPassword);
        winston.info('User changed password successfully:', dbResult);

        res.status(200).json({ message: 'Password reset successful', data: result });
    } catch (error) {
        res.status(400).json({ message: 'Error confirming password reset', error: error.message });
    }
});


router.get('/check-token-expiration-value', async (req, res) => {
    const token = req.header('x-auth-token');

    if (!token) {
        return res.status(400).json({ message: 'Token is required' });
    }

    try {
        const decodedToken = jwt_decode(token.substring(7, token.length));

        // Get expiration time (exp) from the token payload
        const exp = decodedToken.exp;

        // Get the current time in Unix format (seconds)
        const currentTime = Math.floor(Date.now() / 1000);


        res.status(200).json({ message: 'Data decoded', exp: exp, currentTime: currentTime });
    } catch (error) {
        res.status(400).json({ message: 'Error data decoded', error: error.message });
    }

});

router.get('/check-token-validity', async (req, res) => {
    const token = req.header('x-auth-token');

    if (!token) {
        return res.status(400).json({ message: 'Token is required' });
    }

    try {
        const decodedToken = jwt_decode(token.substring(7, token.length));

        // Get expiration time (exp) from the token payload
        const exp = decodedToken.exp;

        // Get the current time in Unix format (seconds)
        const currentTime = Math.floor(Date.now() / 1000);

        const isExpired = exp < currentTime;

        // Check if the token has expired
        if (isExpired) {
            return res.status(401).json({ message: 'The token has expired.', isExpired: isExpired });
        }

        res.status(200).json({ message: 'The token is valid.', isExpired: isExpired });
    } catch (error) {
        res.status(400).json({ message: 'Error token validity', error: error.message });
    }

});


const validate = data => {
    const schema = Joi.object({
        username: Joi.string().min(5).max(255).required(),
        // name: Joi.string().min(5).max(255).required(),
        email: Joi.string().min(5).max(255).required().email(),
        password: Joi.string().min(8).max(255).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
            'password').required(),
        phone_number: Joi.string().min(5).max(255).required(),
        given_name: Joi.string().min(5).max(255).required(),
        family_name: Joi.string().min(5).max(255).required(),
    });
    return schema.validate(data);
};


const validateConfirmationCode = data => {
    const schema = Joi.object({
        username: Joi.string().min(5).max(255).required(),
        confirmationCode: Joi.string().min(6).max(10).required(),
    });
    return schema.validate(data);
};

const validateLogin = data => {
    const schema = Joi.object({
        username: Joi.string().min(5).max(255).required(),
        password: Joi.string().min(8).max(255).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
            'password').required(),
    });
    return schema.validate(data);
};

const validateLoginWithID = data => {
    const schema = Joi.object({
        userid: Joi.string().min(5).max(255).required(),
        username: Joi.string().min(5).max(255).required(),
        password: Joi.string().min(8).max(255).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
            'password').required(),
    });
    return schema.validate(data);
};

const validateUsernameAndToken = data => {
    const schema = Joi.object({
        username: Joi.string().min(5).max(255).required(),
        refreshToken: Joi.string().min(1).required(),
    });
    return schema.validate(data);
};

const validateUsername = data => {
    const schema = Joi.object({
        username: Joi.string().min(5).max(255).required(),
    });
    return schema.validate(data);
};

const validateConfirmReset = data => {
    const schema = Joi.object({
        username: Joi.string().min(5).max(255).required(),
        confirmationCode: Joi.string().min(6).max(10).required(),
        newPassword: Joi.string().min(8).max(255).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
            'password').required(),
    });
    return schema.validate(data);
};

const validateAccessToken = data => {
    const schema = Joi.object({
        accessToken: Joi.string().min(1).required(),
    });
    return schema.validate(data);
};


module.exports = router;

