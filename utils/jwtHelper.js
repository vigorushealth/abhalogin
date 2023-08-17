const jwt = require("jsonwebtoken");
const { SECRET_KEY } = process.env;

/**
 *
 * @param {Record<string, any>} payload payload to store in the token
 * @param {string | number | undefined} expiry
 * @returns {string} jwt signed token
 */
const generateJwtToken = (payload, expiry = undefined) =>
  jwt.sign(payload, SECRET_KEY, {
    ...(expiry && { expiresIn: expiry }),
  });

/**
 *
 * @param {string} token jwt token to verify
 * @returns
 */
const verifyJwtToken = (token) => jwt.verify(token, SECRET_KEY);

module.exports = {
  generateJwtToken,
  verifyJwtToken,
};