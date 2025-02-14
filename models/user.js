// const pool = require('../db');  // Import the PostgreSQL connection pool
const client = require('../startup/db');
const winston = require('winston');

// Create a new user
async function createUser(name, email, password, username) {
  const query = {
    text: 'INSERT INTO users(name, email, password, username) VALUES($1, $2, $3, $4) RETURNING *',
    values: [name, email, password, username],
  };

  try {
    const res = await client.query(query);
    winston.info('User created:', res.rows[0]);
    return res;
  } catch (err) {
    winston.error('Error creating user:', err);
    return err;
  }
}

// Get all users
async function getUsers() {
  try {
    const res = await client.query('SELECT * FROM users');
    winston.info('Users:', res.rows);
    return res.rows;
  } catch (err) {
    winston.error('Error fetching users:', err);
  }
}

// Get a single user by email
async function getUserByEmail(email) {
  const query = {
    text: 'SELECT * FROM users WHERE email = $1',
    values: [email],
  };

  try {
    const res = await client.query(query);
    winston.info('Found Users:', res.rows);
    return res.rows[0];
  } catch (err) {
    winston.error('Error fetching user by email:', err);
    return err;
  }
}

// Get a single user by email
async function getUserByUsername(username) {
  const query = {
    text: 'SELECT * FROM users WHERE username = $1',
    values: [username],
  };

  try {
    const res = await client.query(query);
    winston.info('Found Users:', res.rows);
    return res.rows[0];
  } catch (err) {
    winston.error('Error fetching user by username:', err);
    return err;
  }
}


// Update a user
async function updateUser(id, name, email, password) {
  const query = {
    text: 'UPDATE users SET name = $1, email = $2, password = $3 WHERE id = $4 RETURNING *',
    values: [name, email, password, id],
  };

  try {
    const res = await client.query(query);
    winston.info('User updated:', res.rows[0]);
  } catch (err) {
    winston.error('Error updating user:', err);
  }
}

// Delete a user by ID
async function deleteUser(id) {
  const query = {
    text: 'DELETE FROM users WHERE id = $1 RETURNING *',
    values: [id],
  };

  try {
    const res = await client.query(query);
    winston.info('User deleted:', res.rows[0]);
  } catch (err) {
    winston.error('Error deleting user:', err);
  }
}


// Update a user
async function updatePassword(id, password) {
  const query = {
    text: 'UPDATE users SET password = $1 WHERE id = $2 RETURNING *',
    values: [password, id],
  };

  try {
    const res = await client.query(query);
    winston.info('User updated:', res.rows[0]);
  } catch (err) {
    winston.error('Error updating user:', err);
  }
}


module.exports = {
  createUser,
  getUsers,
  getUserByEmail,
  updateUser,
  deleteUser,
  getUserByUsername,
  updatePassword,
};
