
const { Pool, Client } = require('pg');
const winston = require('winston');
const dotenv = require('dotenv');
const config = require('config');

// Load environment variables from .env file
dotenv.config();



// const conString = config.get('db') || process.env.POSTGRES_CON_STR;
const conString = process.env.POSTGRES_CON_STR;
var client = new Client(conString);


const connectToDatabase = async () => {
    try {
        // await pool.connect();
        await client.connect();
        winston.info(`Successfully connected to PostgreSQL database ${conString}...`);
    } catch (error) {
        winston.error(`Error connecting to PostgreSQL database: ${error.message}`);
    }
};


connectToDatabase().catch((err) => {
    winston.error(`App failed to start: ${err.message}`);
    process.exit(1); // Exit the process if the database connection fails
});


module.exports = client;