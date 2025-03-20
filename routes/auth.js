const Joi = require("joi");
const bcrypt = require("bcrypt");
const _ = require("lodash");
const winston = require("winston");
const express = require("express");
const router = express.Router();
const dotenv = require("dotenv");
const AWS = require("aws-sdk");
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const jwt_decode = require("jwt-decode");
const jwt = require("jsonwebtoken");
const {
  createUser,
  getUsers,
  getUserByEmail,
  updateUser,
  deleteUser,
  getUserByUsername,
  updatePassword,
  updateUserConfirmation,
  updateAttemptsAndLocked,
  resetAttemptsAndLocked,
} = require("../models/user");

const axios = require("axios");
const { Issuer, generators } = require("openid-client");

dotenv.config();

const UserPoolId = process.env.AWS_COGNITO_USER_POOL_ID;
const ClientId = process.env.AWS_COGNITO_CLIENT_ID;
const Region = process.env.AWS_COGNITO_REGION;

AWS.config.update({ region: Region }); // Replace with your AWS region

const poolData = {
  UserPoolId,
  ClientId,
};

router.post("/login", async (req, res) => {
  const { userid, username, password } = req.body;

  if (userid) {
    console.log("validateLoginWithID");
    const { error } = validateLoginWithID(req.body);
    if (error)
      return res
        .status(400)
        .json({ message: "Validation Error", error: error.details[0].message });
  } else {
    console.log("validateLogin");
    const { error } = validateLogin(req.body);
    if (error)
      return res
        .status(400)
        .json({ message: "Validation Error", error: error.details[0].message });
  }

  let user = await getUserByUsername(username);
  if (!user)
    return res
      .status(400)
      .json({ message: "Username not exist", error: "Username not exist" });

  if (userid) {
    if (user.contractornumber != userid)
      return res.status(400).json({
        message: "User ID is incorrect",
        error: "User ID is incorrect",
      });
  }

  if (!user.isconfirm)
    return res.status(400).json({
      message: "User is nor confirmed prior authentication",
      error: "User is nor confirmed prior authentication",
    });

  // check password locked
  if (user.locked)
    return res
      .status(423)
      .json({ message: "User locked error", error: "User locked error" });

  const validPassword = await bcrypt.compare(password, user.password);
  const updatedAttempts = user.attempts + 1;
  // if (!validPassword) return res.status(400).json({ message: 'Invalid Password', error: "Invalid Password" });

  if (!validPassword) {
    // database
    const maxAttempts = process.env.APP_114BK_MAX_PASSWORD_ATTEMPTS;
    const isLocked = updatedAttempts >= maxAttempts ? true : false;

    const result = await updateAttemptsAndLocked(
      user.id,
      updatedAttempts,
      isLocked
    );
    winston.info("User attempts and locked updated successfully:", result);

    return res
      .status(400)
      .json({ message: "Invalid Password", error: "Invalid Password" });
  }

  const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

  const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(
    {
      Username: username,
      Password: password,
    }
  );

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

    const result = await updateAttemptsAndLocked(user.id, 0, false);
    winston.info(
      "User attempts and locked set to default successfully:",
      result
    );

    winston.info(authResult);
    res.status(200).json({
      message: "Login successful",
      accessToken: accessToken,
      idToken: idToken,
      refreshToken: refreshToken,
    });
  } catch (error) {
    winston.error("Error login user:", error);
    res.status(400).json({ message: "Login failed", error: error.message });
  }
});

router.post("/signup", async (req, res) => {
  const { error } = validate(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  // const { username, name, given_name, family_name, phone_number, email, password } = req.body;
  const { username, given_name, family_name, phone_number, email, password } =
    req.body;

  let user = await getUserByEmail(email);
  if (user)
    return res.status(400).json({
      message: "Invalid email or password",
      error: "Invalid email or password",
    });

  const salt = await bcrypt.genSalt(15);
  const hashedPassword = await bcrypt.hash(password, salt);

  try {
    const attributeList = [
      new AmazonCognitoIdentity.CognitoUserAttribute({
        Name: "email",
        Value: email,
      }),
    ];

    attributeList.push(
      new AmazonCognitoIdentity.CognitoUserAttribute({
        Name: "phone_number",
        Value: phone_number,
      })
    );

    attributeList.push(
      new AmazonCognitoIdentity.CognitoUserAttribute({
        Name: "given_name",
        Value: given_name,
      })
    );

    attributeList.push(
      new AmazonCognitoIdentity.CognitoUserAttribute({
        Name: "family_name",
        Value: family_name,
      })
    );

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

    const result = await createUser(
      name,
      email,
      hashedPassword,
      username,
      isConfirm,
      contractor_number
    );
    winston.info("User created successfully:", result.rows[0]);
    res
      .status(201)
      .send(_.pick(result.rows[0], ["id", "name", "email", "username"]));
  } catch (err) {
    winston.error("Error creating user:", err);
    // res.status(400).send(err);
    res.status(400).json({ message: "Sign-up Error!", data: err });
  }
});

router.post("/confirm", async (req, res) => {
  const { username, confirmationCode } = req.body;

  const { error } = validateConfirmationCode(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  let user = await getUserByUsername(username);
  if (!user)
    return res
      .status(400)
      .json({ message: "Username not exist!", error: "Username not exist!" });

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
    winston.info("User changed isConfirm value successfully:", dbResult);

    res
      .status(200)
      .json({ message: "User confirmed successfully", data: result });
  } catch (error) {
    winston.error("Error confirming registration:", error);
    res
      .status(400)
      .json({ message: "Error confirming registration", error: error.message });
  }
});

router.post("/resend-confirmation-code", async (req, res) => {
  const { username } = req.body;

  const { error } = validateUsername(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  let user = await getUserByUsername(username);
  if (!user)
    return res
      .status(400)
      .json({ message: "Username not exist!", error: "Username not exist!" });

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

    winston.info("User sent new code successfully:", result);

    res.status(200).json({ message: "User sent new code", data: result });
  } catch (error) {
    winston.error("Error confirming registration:", error);
    res
      .status(400)
      .json({ message: "Error confirming registration", error: error.message });
  }
});

router.post("/refresh-token", async (req, res) => {
  const { refreshToken, username } = req.body;

  const { error } = validateUsernameAndToken(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  let user = await getUserByUsername(username);
  if (!user)
    return res
      .status(400)
      .json({ message: "Username not exist!", error: "Username not exist!" });

  const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

  const userData = {
    Username: username, // You need to pass the username
    Pool: userPool,
  };

  const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

  const refreshTokenObj = new AmazonCognitoIdentity.CognitoRefreshToken({
    RefreshToken: refreshToken,
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
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    winston.error("Error during token refresh:", err);
    res
      .status(500)
      .json({ message: "Token refresh failed", error: err.message });
  }
});

// Logout user (clear the session)
router.post("/logout", async (req, res) => {
  const { username } = req.body;

  const { error } = validateUsername(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  let user = await getUserByUsername(username);
  if (!user)
    return res
      .status(400)
      .json({ message: "Username not exist!", error: "Username not exist!" });

  const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

  const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
    Username: username,
    Pool: userPool,
  });

  try {
    cognitoUser.signOut();
    res.status(200).json({ message: "User logged out successfully" });
  } catch (error) {
    res
      .status(400)
      .json({ message: "Error logging out", error: error.message });
  }
});

// Password Reset - Initiate Forgot Password Flow
router.post("/forgot-password", async (req, res) => {
  const { username } = req.body;

  const { error } = validateUsername(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  let user = await getUserByUsername(username);
  if (!user)
    return res
      .status(400)
      .json({ message: "Username not exist!", error: "Username not exist!" });

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
    res
      .status(200)
      .json({ message: "Password reset email sent", data: result });
  } catch (error) {
    res
      .status(400)
      .json({ message: "Error sending reset email", error: error.message });
  }
});

// Confirm Password Reset
router.post("/confirm-reset-password", async (req, res) => {
  const { username, confirmationCode, newPassword } = req.body;

  const { error } = validateConfirmReset(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  let user = await getUserByUsername(username);
  if (!user)
    return res
      .status(400)
      .json({ message: "Username not exist!", error: "Username not exist!" });

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
    winston.info("User changed password successfully:", dbResult);

    res
      .status(200)
      .json({ message: "Password reset successful", data: result });
  } catch (error) {
    res.status(400).json({
      message: "Error confirming password reset",
      error: error.message,
    });
  }
});

router.get("/check-token-expiration-value", async (req, res) => {
  const token = req.header("x-auth-token");

  if (!token) {
    return res.status(400).json({ message: "Token is required" });
  }

  try {
    const decodedToken = jwt_decode(token.substring(7, token.length));

    // Get expiration time (exp) from the token payload
    const exp = decodedToken.exp;

    // Get the current time in Unix format (seconds)
    const currentTime = Math.floor(Date.now() / 1000);

    res
      .status(200)
      .json({ message: "Data decoded", exp: exp, currentTime: currentTime });
  } catch (error) {
    res
      .status(400)
      .json({ message: "Error data decoded", error: error.message });
  }
});

router.get("/check-token-validity", async (req, res) => {
  const token = req.header("x-auth-token");

  if (!token) {
    return res.status(400).json({ message: "Token is required" });
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
      return res
        .status(401)
        .json({ message: "The token has expired.", isExpired: isExpired });
    }

    res
      .status(200)
      .json({ message: "The token is valid.", isExpired: isExpired });
  } catch (error) {
    res
      .status(400)
      .json({ message: "Error token validity", error: error.message });
  }
});

router.post("/reset-password-attempts-locked", async (req, res) => {
  const { username } = req.body;

  const { error } = validateUsername(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  let user = await getUserByUsername(username);
  if (!user)
    return res
      .status(400)
      .json({ message: "Username not exist!", error: "Username not exist!" });

  try {
    const result = await updateAttemptsAndLocked(user.id, 0);
    winston.info(
      "User resets password attempts and locked successfully:",
      result
    );

    res.status(200).json({
      message: "User resets password attempts and locked successfully",
      data: result,
    });
  } catch (error) {
    winston.error("Error in resetting password attempts and locked:", error);
    res.status(400).json({
      message: "Error in resetting password attempts and locked",
      error: error.message,
    });
  }
});

//SAML - workflow
router.get("/sso-login", (req, res) => {
  // const loginUrl = `https://ap-southeast-1edoxsdemx.auth.ap-southeast-1.amazoncognito.com/login?response_type=code&client_id=5ols6e05j2f7ah0angckt0h1p&redirect_uri=http://localhost:3000/api/auth/callback`;

  const loginUrl = `${process.env.SAML_COGNITO_DOMAIN}/login?response_type=code&client_id=${process.env.SAML_COGNITO_APP_CLIENT_ID}&redirect_uri=${process.env.SAML_COGNITO_REDIRECT_URI}`;

  res.redirect(302, loginUrl);
});

router.get("/callback", async (req, res) => {
  try {
    // const authorizationCode = req.header("x-auth-code");

    const authorizationCode = req.query.code;

    if (!authorizationCode) {
      return res.status(400).json({ error: "Authorization code not found" });
    }

    // Prepare data to send to AWS Cognito for token exchange
    // const tokenData = new URLSearchParams();
    // tokenData.append("grant_type", "authorization_code");
    // tokenData.append("code", authorizationCode);
    // tokenData.append("redirect_uri", "http://localhost:3000/api/auth/callback");
    // tokenData.append("client_id", "5ols6e05j2f7ah0angckt0h1p");
    // tokenData.append(
    //   "client_secret",
    //   "hhspnat3lt3c6ebe5iv15d4846p9mungoqbf0is8pnd1b6pt3qu"
    // );

    const redirectUri = `${process.env.SAML_COGNITO_REDIRECT_URI}`;
    const clientId = `${process.env.SAML_COGNITO_APP_CLIENT_ID}`;
    const clientSecret = `${process.env.SAML_COGNITO_APP_CLIENT_SECRET}`; // If using public app client, leave empty.

    const tokenData = new URLSearchParams();
    tokenData.append("grant_type", "authorization_code");
    tokenData.append("code", authorizationCode);
    tokenData.append("redirect_uri", redirectUri);
    tokenData.append("client_id", clientId);
    tokenData.append("client_secret", clientSecret);

    // Send a POST request to AWS Cognito token endpoint
    const response = await axios.post(
      // "https://ap-southeast-1edoxsdemx.auth.ap-southeast-1.amazoncognito.com/oauth2/token",
      `${process.env.SAML_COGNITO_DOMAIN}/oauth2/token`,
      tokenData,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const { access_token, id_token, refresh_token } = response.data;

    const decodedToken = jwt_decode(
      access_token.substring(7, access_token.length)
    );

    const decodedIDToken = jwt_decode(id_token.substring(7, id_token.length));

    // Get expiration time (exp) from the token payload
    const username = decodedToken.username;

    const name = decodedIDToken.name;
    // res.status(200).json({
    //   message: "SSO Authorization successfully",
    //   accessToken: access_token,
    //   idToken: id_token,
    //   refreshToken: refresh_token,
    //   username: username,
    // });

    // const loginUrl = `http://localhost:5173/callback?username=${username}&idToken=${id_token}&accessToken=${access_token}&refreshToken=${refresh_token}  `;

    const loginUrl = `${process.env.SAML_APP_114BK_URL_COOKIES}?username=${username}&idToken=${id_token}&accessToken=${access_token}&refreshToken=${refresh_token}  `;

    // const loginUrl = `http://localhost:5173/callback`;

    res.cookie("username", username, { httpOnly: false, secure: true });
    res.cookie("name", name, { httpOnly: false, secure: true });
    res.cookie("accessToken", access_token, { httpOnly: false, secure: true });
    res.cookie("idToken", id_token, { httpOnly: false, secure: true });
    res.cookie("refreshToken", refresh_token, {
      httpOnly: false,
      secure: true,
    });

    res.redirect(302, loginUrl);
  } catch (error) {
    winston.error("Error in sso Authorization:", error);
    res
      .status(400)
      .json({ message: "Error in sso Authorization", error: error.message });
  }
});

// router.post('/sso-oidc-logout', (req, res) => {
//     try{

//     const logoutUrl = 'https://ap-southeast-1edoxsdemx.auth.ap-southeast-1.amazoncognito.com/logout?client_id=5ols6e05j2f7ah0angckt0h1p&logout_uri=http://localhost:3000/api/auth/sso-login'
//     res.redirect(logoutUrl);

//     } catch (error) {
//         winston.error('sso-logout:', error);
//         res.status(400).json({ message: 'sso-logout', error: error.message });
//     }

// });

router.post("/sso-logout", (req, res) => {
  const { redirect_uri } = req.body;

  const { error } = validateRedirectUri(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  const logoutUrl = `https://dev-6l3hmjbxqs3e023h.us.auth0.com/authorize?client_id=Qbpz90btaGt56VksXQkhkM41SoJswd6s&response_type=code&redirect_uri=http://localhost:3000/api/auth/sso-saml-logout&scope=openid profile email`;

  // Redirect to Cognito Hosted UI for login
  res.redirect(302, logoutUrl);
});

router.get("/sso-saml-logout", (req, res) => {
  try {
    // const logoutUrl = 'https://ap-southeast-1edoxsdemx.auth.ap-southeast-1.amazoncognito.com/logout?client_id=5ols6e05j2f7ah0angckt0h1p&logout_uri=http://localhost:3000/api/auth/sso-login'
    // res.redirect(logoutUrl);

    const authorizationCode = req.query;
    console.log("authorizationCode: ", authorizationCode);

    // const logoutUrl = `https://dev-6l3hmjbxqs3e023h.us.auth0.com/v2/logout?returnTo=https://jwt.io&client_id=Qbpz90btaGt56VksXQkhkM41SoJswd6s`;

    const logoutUrl = `https://dev-6l3hmjbxqs3e023h.us.auth0.com/v2/logout?returnTo=http://localhost:5173/callbackOut&client_id=Qbpz90btaGt56VksXQkhkM41SoJswd6s`;

    res.redirect(302, logoutUrl);
  } catch (error) {
    winston.error("sso-logout:", error);
    res.status(400).json({ message: "sso-logout", error: error.message });
  }
});

//OIDC - workflow
async function configureCognitoClient() {
  try {
    const issuer = await Issuer.discover(
      // "https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_1bJCXtPsY"
      `https://cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`
    );

    // Create the client with credentials
    const cognitoClient = new issuer.Client({
      // client_id: "mairj2l0292h0fh1fqpeghh3u",
      // client_secret: "uqbkhk553dd71ics4a1d3aqsmiqv65fk4ah0pikmdgqeea8m7h",
      // redirect_uris: ["http://localhost:3000/api/auth/oidc/callback"],
      // response_types: ["code"],
      client_id: `${process.env.COGNITO_APP_CLIENT_ID}`,
      client_secret: `${process.env.COGNITO_APP_CLIENT_SECRET}`,
      redirect_uris: [`${process.env.COGNITO_REDIRECT_URI}`],
      response_types: ["code"],
    });

    console.log("Cognito Client successfully configured.");
    return cognitoClient;
    // Use cognitoClient for further authentication flow...
  } catch (err) {
    console.error("Error discovering Cognito OIDC issuer:", err);
  }
}

let cognitoClient;

router.get("/sso-oidc-login", async (req, res) => {
  cognitoClient = await configureCognitoClient();

  const authorizationUrl = cognitoClient.authorizationUrl({
    scope: "openid profile email", // Scopes for the requested permissions
  });
  res.redirect(302, authorizationUrl);
});

router.get("/oidc/callback", async (req, res) => {
  try {
    const authorizationCode = req.query.code;

    if (!authorizationCode) {
      return res.status(400).json({ error: "Authorization code not found" });
    }

    // const redirectUri = "http://localhost:3000/api/auth/oidc/callback";
    // const clientId = "mairj2l0292h0fh1fqpeghh3u";
    // const clientSecret = "uqbkhk553dd71ics4a1d3aqsmiqv65fk4ah0pikmdgqeea8m7h"; // If using public app client, leave empty.

    const redirectUri = `${process.env.COGNITO_REDIRECT_URI}`;
    const clientId = `${process.env.COGNITO_APP_CLIENT_ID}`;
    const clientSecret = `${process.env.COGNITO_APP_CLIENT_SECRET}`; // If using public app client, leave empty.

    const tokenData = new URLSearchParams();
    tokenData.append("grant_type", "authorization_code");
    tokenData.append("code", authorizationCode);
    tokenData.append("redirect_uri", redirectUri);
    tokenData.append("client_id", clientId);
    tokenData.append("client_secret", clientSecret);

    const tokenResponse = await axios.post(
      // "https://ap-southeast-11bjcxtpsy.auth.ap-southeast-1.amazoncognito.com/oauth2/token",
      `${process.env.COGNITO_DOMAIN}/oauth2/token`,
      tokenData,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const { access_token, id_token, refresh_token } = tokenResponse.data;

    const decodedToken = jwt_decode(
      access_token.substring(7, access_token.length)
    );

    // Get expiration time (exp) from the token payload
    const username = decodedToken.username;

    // res.status(200).json({
    //   message: "SSO Authorization successfully",
    //   accessToken: access_token,
    //   idToken: id_token,
    //   refreshToken: refresh_token,
    // });

    // const loginUrl = `http://localhost:5173/callback?username=${username}&idToken=${id_token}&accessToken=${access_token}&refreshToken=${refresh_token}  `;

    const loginUrl = `${process.env.APP_114BK_URL_COOKIES}?username=${username}&idToken=${id_token}&accessToken=${access_token}&refreshToken=${refresh_token}  `;

    // const loginUrl = `http://localhost:5173/callback`;

    res.cookie("username", username, { httpOnly: false, secure: true });
    res.cookie("accessToken", access_token, { httpOnly: false, secure: true });
    res.cookie("idToken", id_token, { httpOnly: false, secure: true });
    res.cookie("refreshToken", refresh_token, {
      httpOnly: false,
      secure: true,
    });

    res.redirect(302, loginUrl);
  } catch (error) {
    console.error("Error during callback processing:", error);
    res
      .status(400)
      .json({ message: "Error in sso Authorization", error: error.message });
  }
});

//OIDC - workflow - Auth0
// async function configureCognitoClient() {
//   try {
//     const issuer = await Issuer.discover(
//       "https://ap-southeast-11bjcxtpsy.auth.ap-southeast-1.amazoncognito.com"
//     );

//     // Create the client with credentials
//     const cognitoClient = new issuer.Client({
//       client_id: "3rf5bc42r8lkpqil7flfm225hs",
//       client_secret: "nfju2i7d72mmff813f49nv78jovge6tqr6u15qd12fsk9grs22e",
//       redirect_uris: ["http://localhost:3000/api/auth//oidc/callback"],
//       response_types: ["code"],
//     });

//     console.log("Cognito Client successfully configured.");
//     return cognitoClient;
//     // Use cognitoClient for further authentication flow...
//   } catch (err) {
//     console.error("Error discovering Cognito OIDC issuer:", err);
//   }
// }

// let cognitoClient;

// router.get("/sso-oidc-login", async (req, res) => {
//   cognitoClient = await configureCognitoClient();

//   const authorizationUrl = cognitoClient.authorizationUrl({
//     scope: "openid profile email", // Scopes for the requested permissions
//   });
//   res.redirect(302, authorizationUrl);
// });

// router.get("/oidc/callback", async (req, res) => {
//   try {
//     const authorizationCode = req.query.code;

//     if (!authorizationCode) {
//       return res.status(400).json({ error: "Authorization code not found" });
//     }

//     const redirectUri = "http://localhost:3000/api/auth/oidc/callback";
//     const clientId = "3rf5bc42r8lkpqil7flfm225hs";
//     const clientSecret = "nfju2i7d72mmff813f49nv78jovge6tqr6u15qd12fsk9grs22e"; // If using public app client, leave empty.

//     const tokenData = new URLSearchParams();
//     tokenData.append("grant_type", "authorization_code");
//     tokenData.append("code", authorizationCode);
//     tokenData.append("redirect_uri", redirectUri);
//     tokenData.append("client_id", clientId);
//     tokenData.append("client_secret", clientSecret);

//     const response = await axios.post(
//       "https://ap-southeast-11bjcxtpsy.auth.ap-southeast-1.amazoncognito.com/oauth2/token",
//       tokenData,
//       {
//         headers: {
//           "Content-Type": "application/x-www-form-urlencoded",
//         },
//       }
//     );

//     const { access_token, id_token, refresh_token } = response.data;

//     res.status(200).json({
//       message: "SSO Authorization successfully",
//       accessToken: access_token,
//       idToken: id_token,
//       refreshToken: refresh_token,
//     });

//     // const params = cognitoClient.callbackParams(req);
//     // const tokenSet = await cognitoClient.callback(
//     //   "http://localhost:3000/api/auth//oidc/callback",
//     //   params
//     // );
//     // res.status(200).json({ tokenSet: tokenSet });

//     // const loginUrl = `http://localhost:5173/member-callback?username=${username}&idToken=${id_token}&accessToken=${access_token}&refreshToken=${refresh_token}  `;

//     // res.redirect(302, loginUrl);
//   } catch (error) {
//     console.error("Error during callback processing:", error);
//     res
//       .status(400)
//       .json({ message: "Error in sso Authorization", error: error.message });
//   }
// });

router.post("/sso-member-logout", (req, res) => {
  const { redirect_uri } = req.body;

  const { error } = validateRedirectUri(req.body);
  if (error)
    return res
      .status(400)
      .json({ message: "Validation Error", error: error.details[0].message });

  const logoutUrl = `https://dev-6l3hmjbxqs3e023h.us.auth0.com/authorize?client_id=ivSXmKwiPcBrz9B9YcZr3Gf5VmRDMmpU&response_type=code&redirect_uri=http://localhost:3000/api/auth/sso-oidc-logout&scope=openid profile email`;

  // Redirect to Cognito Hosted UI for login
  res.redirect(302, logoutUrl);
});

router.get("/sso-oidc-logout", (req, res) => {
  try {
    const authorizationCode = req.query;
    console.log("authorizationCode: ", authorizationCode);

    // const logoutUrl = `https://dev-6l3hmjbxqs3e023h.us.auth0.com/v2/logout?returnTo=https://jwt.io&client_id=Qbpz90btaGt56VksXQkhkM41SoJswd6s`;

    const logoutUrl = `https://dev-6l3hmjbxqs3e023h.us.auth0.com/v2/logout?returnTo=http://localhost:5173/callbackOut&client_id=ivSXmKwiPcBrz9B9YcZr3Gf5VmRDMmpU`;

    res.redirect(302, logoutUrl);
  } catch (error) {
    winston.error("sso-oidc-logout:", error);
    res.status(400).json({ message: "sso-oidc-logout", error: error.message });
  }
});

const validate = (data) => {
  const schema = Joi.object({
    username: Joi.string().min(5).max(255).required(),
    // name: Joi.string().min(5).max(255).required(),
    email: Joi.string().min(5).max(255).required().email(),
    password: Joi.string()
      .min(8)
      .max(255)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        "password"
      )
      .required(),
    phone_number: Joi.string().min(5).max(255).required(),
    given_name: Joi.string().min(5).max(255).required(),
    family_name: Joi.string().min(5).max(255).required(),
  });
  return schema.validate(data);
};

const validateConfirmationCode = (data) => {
  const schema = Joi.object({
    username: Joi.string().min(5).max(255).required(),
    confirmationCode: Joi.string().min(6).max(10).required(),
  });
  return schema.validate(data);
};

const validateLogin = (data) => {
  const schema = Joi.object({
    username: Joi.string().min(5).max(255).required(),
    password: Joi.string()
      .min(8)
      .max(255)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        "password"
      )
      .required(),
  });
  return schema.validate(data);
};

const validateLoginWithID = (data) => {
  const schema = Joi.object({
    userid: Joi.string().min(5).max(255).required(),
    username: Joi.string().min(5).max(255).required(),
    password: Joi.string()
      .min(8)
      .max(255)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        "password"
      )
      .required(),
  });
  return schema.validate(data);
};

const validateUsernameAndToken = (data) => {
  const schema = Joi.object({
    username: Joi.string().min(5).max(255).required(),
    refreshToken: Joi.string().min(1).required(),
  });
  return schema.validate(data);
};

const validateUsername = (data) => {
  const schema = Joi.object({
    username: Joi.string().min(5).max(255).required(),
  });
  return schema.validate(data);
};

const validateConfirmReset = (data) => {
  const schema = Joi.object({
    username: Joi.string().min(5).max(255).required(),
    confirmationCode: Joi.string().min(6).max(10).required(),
    newPassword: Joi.string()
      .min(8)
      .max(255)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        "password"
      )
      .required(),
  });
  return schema.validate(data);
};

const validateAccessToken = (data) => {
  const schema = Joi.object({
    accessToken: Joi.string().min(1).required(),
  });
  return schema.validate(data);
};

const validateRedirectUri = (data) => {
  const schema = Joi.object({
    redirect_uri: Joi.string().min(1).uri().required(),
  });
  return schema.validate(data);
};

module.exports = router;
