const config = require('./config.json').development; //TODO: Use NODE_ENV
const path = require('path');
const express = require('express')
const bodyParser = require('body-parser')
const app = express();
const helmet = require('helmet');
const morgan = require('morgan');
const cors = require('cors')
const oAuthModel = require('./authorization/accessTokenModel');
const oAuth2Server = require('oauth2-server');
app.oauth = new oAuth2Server({  //TODO: Add oauth configurations to config.json
    model: oAuthModel,
    grants: ['password', 'authorization_code', 'refresh_token'],
    debug: true,
    allowExtendedTokenAttributes: true, 
    accessTokenLifetime: 300,
    refreshTokenLifetime: 600
})

const rootDirectoryPath = require('./utils/path');

const authRoutes = require('./routes/auth')(express.Router(), app);
const oauth2Routes = require('./routes/oauth2')(express.Router(), app);
const profileRoutes = require('./routes/profile')(express.Router(), app);
const fcmRoutes = require('./routes/fcm')(express.Router(), app);
const oauth2RestrictedRoutes = require('./routes/oauth2Restricted')(express.Router(), app);
const internalRoutes = require('./routes/internal')(express.Router(), app);
const undefinedRoutes = require('./routes/undefined');
// const restrictedAreaRoutes = require('./routes/restrictedAreaRoutes')(express.Router(), app, restrictedAreaController);
const {createMySqlPool} = require('./database/mysql')
const {initializeFCMConnection} = require('./controllers/fcm')
const handlingErrors =  require('./middleware/error')
require('express-async-errors')

const logger = require('./logs/logger').createLogger

process.on('uncaughtException', (ex) => {
    console.log('-----'+ex)
    logger.error("uncaughtException: "+ex)
    if(ex.code === 'EADDRINUSE' && ex.syscall === 'listen') process.exit();
})

process.on('unhandledRejection', (ex) => {
    console.log(ex);
    throw ex;
})

app.use(helmet());
app.use(morgan('combined'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(rootDirectoryPath, 'uploads')))

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*'); //2nd parameter could also be used for restriction, for example - 'http://my-cool-page.com', but we barely want to narrow it down to one, Note - It will still work with tools like POSTMAN
    res.header(
        'Access-Control-Allow-Headers', 
        'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-API-KEY'
    );
    if (req.method === 'OPTIONS') { //Browser sends an OPTIONS request first when we send a POST or PUT Request to check whether we can make that request
        res.header('Access-Control-Allow-Methods', 'PUT, POST, PATCH, DELETE, GET'); //Adding this header will let the browser know what METHODS it may send
        return res.status(200).json({}); //Since we dont need to process this request METHOD any further we simply send the response back at this stage itself
    }
    next();
});

app.use(cors())

// app.get('/', (req, res) => res.send(JSON.stringify('Indhi REST API Server')))

app.use('/auth', authRoutes);
app.use('/auth', oauth2Routes);
app.use('/restricted', profileRoutes);
app.use('/restricted', fcmRoutes);
app.use('/restricted', oauth2RestrictedRoutes);
app.use('/internal', internalRoutes);

app.use(undefinedRoutes);
app.use(handlingErrors);
// app.use(app.oauth.errorHandler());

createMySqlPool().then(async () => {
    console.log("\x1b[32m",'MySql Database connected')
    app.listen(config.app.port, config.app.ip, () => {
        console.log("\x1b[32m",'IP - '+config.app.ip+ ',Port - '+config.app.port);
    });
    // initializeFCMConnection().then(async () => {
    //     console.log("\x1b[32m",'Initialized FCM connection');
    // }).catch((err) => setImmediate(() => {console.log("\x1b[31m",'Could not initialize FCM connection, error - %s',err)}));
}).catch((err) => setImmediate(() => {console.log("\x1b[31m",'Could not connect to Inventory mysql Database, error - %s',err)}));

module.exports = {
  app
}
