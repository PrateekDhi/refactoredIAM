const oauthServer = require('oauth2-server');

const {oauthErrorHandler} = require('../middleware/oauthErrorHandler');

const Request = oauthServer.Request;
const Response = oauthServer.Response;