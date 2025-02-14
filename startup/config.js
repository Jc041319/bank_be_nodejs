const config = require('config');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();


module.exports = function () {
  // if (!config.get('jwtPrivateKey') || !process.env.APP_114BK_JWTPRIVATEKEY) {
  if (!process.env.APP_114BK_JWTPRIVATEKEY) {
    throw new Error('FATAL ERROR: jwtPrivateKey is not defined.');
  }
}