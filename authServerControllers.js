// authServer/authController.js
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config({ path: path.resolve(process.cwd(), '.env') });
const axios = require('axios');

const BackEndURL = process.env.BACKEND_URL;
const AuthServerURL = process.env.BACKEND_AUTH_URL;
const refreshTokenSecret = process.env.ACCESS_TOKEN_REFRESH;
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const emailTokenSecret = process.env.EMAIL_TOKEN_SECRET;
const FRONTEND_URL = process.env.VITE_FRONTEND_URL;


exports.getUserInfo = async (req, res) => {
  try {
    const response = await axios.get(`${BackEndURL}/user/profile`, {
      params: {
        userID: req.user.userID,
      }
    });
    res.status(200).json(response.data);
  } catch (error) {
    console.error('Error fetching user info from backend:', error.message);
    res.status(500).json({ error: 'Failed to validate user session' });
  }
};

exports.login = async (req, res) => {
  const { emailAddress, password } = req.body;
  try {
    const response = await axios.post(`${BackEndURL}/user/login`, {emailAddress, password});
    const {userID, userType } = response.data;

    const userData = { userID, emailAddress, userType };
    const accessToken = await generateToken(userData, accessTokenSecret, '30m');
    const refreshToken = await generateToken(userData, refreshTokenSecret, '7d');
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000 * 3 , // expires 3 hours
      sameSite: 'None',
      secure: true,
      path: '/',
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000 * 24 * 7, // expires 7 days
      sameSite: 'None',
      secure: true,
      path: '/',
    });
    res.status(200).json({
      message: 'Logged in successfully',
      user: { userType: userData.userType}
    });
  } catch (e) {
    console.error('Login error:', e.message);
    if (e.response) {
      // Pass through the status code and error message from the first endpoint
      return res.status(e.response.status).json({
        error: e.response.data.message || e.response.data.error
      });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.register = async (req, res) => {
  const { firstName, lastName, emailAddress, password, phoneNumber} = req.body;
  try {
    const userData = { firstName, lastName, emailAddress, password, phoneNumber };
    const response = await axios.post(`${BackEndURL}/user/register`, {userData});
    if (!response.data.success) {
      return res.status(500).json({ error: 'registration_error' });
    }
    const user = {
      userID: response.data.userID,
      emailAddress: req.body.emailAddress,
    };

    const token = await generateToken(user, emailTokenSecret, '30m');
    if (!token) {
      return res.status(500).json({ error: 'token_error' });
    }
    const linkSent = await sendVerificationLink(token, emailAddress);
    if (!linkSent) {
      return res.status(500).json({ error: 'verification_link_error' });
    }
    res.status(201).json({ message: 'success_verification_required' });
  } catch (e) {
    console.error('Registration error:', e);
    handleMySqlError(e, res);
  }
};

exports.logout = async (req, res) => {
  res.cookie('accessToken', '', { maxAge: 0 });
  res.cookie('refreshToken', '', { maxAge: 0 });
  res.status(200).json({ message: 'Logged out successfully' });
};

// Frontend - verifyEmail function
exports.verifyEmail = async (req, res) => {
  let message;
  let status = 'fail';

  try {
    const token = req.params.token;

    // **Step 1: Verify the token and extract the email address**
    let emailAddress;
    try {
      const decodedToken = jwt.verify(token, emailTokenSecret);
      emailAddress = decodedToken.emailAddress;
    } catch (error) {
      // Handle token verification errors
      if (error.name === 'JsonWebTokenError') {
        message = 'Invalid token. Please request a new verification email.';
      } else if (error.name === 'TokenExpiredError') {
        message = 'Verification link has expired. Please request a new verification email.';
      } else {
        message = 'Token verification failed. Please try again.';
      }
      console.error('Token verification error:', error.message);
      return res.redirect(`${FRONTEND_URL}/verification-result?status=${status}&message=${encodeURIComponent(message)}`);
    }

    // **Step 2: Fetch the user profile**
    let user;
    try {
      const userResponse = await axios.get(`${BackEndURL}/user/profile`, {
        params: { emailAddress },
      });
      user = userResponse.data.user;
    } catch (error) {
      console.error('Error fetching user profile:', error.message);
      message = 'Error fetching user profile.';
      return res.redirect(`${FRONTEND_URL}/verification-result?status=${status}&message=${encodeURIComponent(message)}`);
    }

    // **Step 3: Check if user exists and is already verified**
    if (!user || !user.userID) {
      console.log('No user found with this email.');
      message = 'No user found with this email.';
    } else if (user.verified === 1) {
      console.log('User with this email has already been verified.');
      message = 'Your email is already verified.';
      status = 'success';
    } else {
      // **Step 4: Verify the user's email**
      try {
        const verifyResponse = await axios.put(`${BackEndURL}/user/verifyEmail`, {
          emailAddress,
        });
        if (verifyResponse && verifyResponse.status === 200) {
          message = 'Email has been verified successfully.';
          status = 'success';
        } else {
          console.log('Failed to verify the email.', verifyResponse);
          message = 'Failed to verify the email.';
        }
      } catch (error) {
        console.error('Error verifying email:', error.message);
        message = 'Error occurred while verifying email.';
      }
    }
  } catch (error) {
    console.error('Unexpected error during email verification:', error.message);
    message = 'Something went wrong during email verification.';
  }

  // **Final Step: Redirect to the verification result page with status and message**
  return res.redirect(
      `${FRONTEND_URL}/verification-result?status=${status}&message=${encodeURIComponent(message)}`
  );
};


async function generateToken(payload, secretKey, expiresIn) {
  try {
    return jwt.sign(payload, secretKey, { expiresIn });
  } catch (e) {
    console.error('Token generation error:', e.message);
    throw e;
  }
}

exports.generateToken = generateToken;

async function sendVerificationLink(token, email) {
  try {
    const url = `${AuthServerURL}/api/auth/verify/${token}`;
    const emailSubject = 'Verify your getValleyTickets account.';

    const emailContent = `
          <p>Hello,</p>
          <p>Please click the following link to verify your email:</p>
          <a href="${url}">Verify Email</a>
        `;
    const emailSent = await axios.post(`${BackEndURL}/email/verify/sendVerification`, {
      email,
      emailSubject,
      emailContent,
    })
    if (emailSent.status !== 200) {
      console.log('Error sending verification link', emailSent);
      return false;
    }

    console.log(`Verification link sent to ${email}`);
    return true;
  } catch (e) {
    console.error('Error sending verification link:', e.message);
    return false;
  }
}
exports.sendVerificationLink = sendVerificationLink;

function handleMySqlError(error, res) {
  switch (error.code) {
    case 'ER_DUP_ENTRY':
      res.status(409).json({ message: 'Email already exists' });
      break;
    case 'ER_BAD_DB_ERROR':
      res.status(500).json({ message: 'Database not found' });
      break;
    case 'ER_PARSE_ERROR':
      res.status(400).json({ message: 'Query syntax error' });
      break;
    case 'ER_NO_REFERENCED_ROW':
    case 'ER_NO_REFERENCED_ROW_2':
      res.status(400).json({ message: 'Foreign key constraint fails' });
      break;
    case 'ER_DATA_TOO_LONG':
      res.status(400).json({ message: 'Data too long for column' });
      break;
    default:
      res.status(500).json({ message: 'Database error', error: error.sqlMessage });
  }
}