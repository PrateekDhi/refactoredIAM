const mysql = require('mysql2');

const pool = mysql.createPool({
    connectionLimit : process.env.MYSQLCONNECTIONLIMIT || 100,
    host     : process.env.MYSQLHOST || config.app_db.host,
    user     : process.env.MYSQLUSER || config.app_db.user,
    password : process.env.MYSQLPASS || config.app_db.password,
    database : process.env.MYSQLDBNAME || config.app_db.database,
    debug    : process.env.MYSQLDEBUGOPTION || false,
    waitForConnections : process.env.MYSQLWAITFORCONNECTIONSOPTION || true,
    queueLimit : process.env.MYSQLQUEUELIMIT || 1000
});

module.exports = pool.promise();