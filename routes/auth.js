const validationMiddleware = require('../middleware/validationMiddleware')

const userController = require('../controllers/user');
const authController = require('../controllers/auth');

module.exports = (router, app) => {
    router.post('/userRegistrationDetails',validationMiddleware, authController.userRegistrationDetails);
    router.post('/usernameSuggestion',validationMiddleware, userController.usernameSuggestion);
    router.post('/userLoginDetails',validationMiddleware,authController.userLoginDetails);
    router.post('/resendEmailOTP',validationMiddleware,authController.resendEmailOTP);
    router.post('/mobileOTPLogin',validationMiddleware,authController.mobileOTPLogin);
    router.post('/resendPhoneOTP',validationMiddleware, authController.resendPhoneOTP);

    router.post('/resetPasswordEmail',validationMiddleware, authController.resetPasswordEmail);

    router.post('/setNewPassword',validationMiddleware, authController.setNewPassword);

    // router.post('/androidVersionCheck',authController.androidVersionCheck);

    // router.post('/updationAndroidVersionCheck',authController.updationAndroidVersionCheck);

    // router.get('/deleteTestUser',userController.deleteTestUser);

    const manageAuthenticationGrantType = (req,res,next) => {
        console.log(req.body)
        if(req.body.grant_type == 'mobile_otp'){
            console.log('Logging in through mobile OTP');
            req.body.username = 'mobile-'+req.body.username
            req.body.grant_type = 'password';
            next();
        }else if(req.body.grant_type == 'email_otp'){
            console.log('Logging in through email OTP');
            req.body.username = 'email-'+req.body.username
            req.body.grant_type = 'password';
            next();
        }else if(req.body.grant_type == 'password'){ //to be changed later
            req.body.username = 'password-'+req.body.username
            next();
        }else if(req.body.grant_type == 'authentication_code'){
            req.body.username = 'code-'+req.body.username
            next();
        }else{
            res
            .status(400)
            .json({"code":452,"message":"Invalid grant type","name":"invalid_fields"});//fields_missing
        }
    }

    const manageRefreshTokenRequest = (req,res,next) => {
        console.log(JSON.stringify(req.headers))
        if(req.body.grant_type == 'refresh_token' && req.body.refresh_token != null && req.body.client_id != null){
            next();
        }else{
            res
            .status(400)
            .json({"code":452,"message":"Invalid grant type","name":"invalid_fields"});
        }
    }

    const tOptions = {
        // Allow token requests using the password grant to not include a client_secret.
        requireClientAuthentication: {password: false, refresh_token:false}
    };

    const obtainToken = (req, res) => {        
        const request = new Request(req);
        const response = new Response(res);
        return app.oauth.token(request, response, tOptions)
        .then(token => {
            res.json(token);
        }).catch( err => {
            console.log("--jjfjkfjkffofj=----")
            console.log("----obtainToken error-----"+err)
            // delete err.statusCode
            if(err.internalCode != null){
                // delete err.statusCode; //same as code
                delete err.status; //same as code
                delete err.code;
                let responseError = {...err}
                responseError.code = responseError.internalCode;
                delete responseError.internalCode;
                delete responseError.statusCode
                res.status(err.statusCode || 500).json(responseError);
            }else{
                res.locals.errObject = err;
                next();
            }
        });
    }
    
    router.post('/getAccessToken',validationMiddleware, manageAuthenticationGrantType, obtainToken, oauthErrorHandler);

    router.post('/refreshToken', validationMiddleware,manageRefreshTokenRequest, obtainToken,  oauthErrorHandler);

    return router
}