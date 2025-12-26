const crypto = require("crypto");

const challenges = {};

function createChallenge(user) {
  const challenge = crypto.randomBytes(32).toString("base64");
  challenges[user] = challenge;
  return challenge;
}

function consumeChallenge(user) {
  const challenge = challenges[user];
  delete challenges[user];
  return challenge;
}

module.exports = {
  createChallenge,
  consumeChallenge,
};
