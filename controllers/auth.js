/**
 *
 * file - auth.js - Authentication controller
 *
 * @version    0.1.0
 * @created    23/10/2021
 * @copyright  Dhi Technologies
 * @license    For use by dhi Technologies applications
 *
 * Description : schema and workflow for rwgistering users
 *
 *
 * 23/10/2021 - RR - Created
 *
 *  
 * TODO: Add a cron job that deletes all the invalidated or used up otps from DB if they are not required for analytics purpose
 * IMPORTANT - 
**/

const cn = require('../utils/common');

//Models
const User = require('../models/user');
const TemporaryUser = require('../models/temporaryUser');
const Otp = require('../models/otp');
const EmailOtp = require('../models/emailOtp');

//Services
const emailOtpServices = require('../services/emailOtp');

exports.userRegistrationDetails = (req, res, next) => {
    //---------------------------------------------
    // @VALIDATIONS
    // 1) Is the client valid -> req.body.client_id
    // 2) Registration form fields validation 
    // 3) Does Email already exist(DB action - User model needed) 
    //--------------------------------------------- 
    let temporaryUserId;   
    Promise.all([
        otpServices.sendEmailOTP(req.body.email.toLowerCase()),
        TemporaryUser.save(req.body.firstName, req.body.lastName, req.body.email.toLowerCase(), req.body.password, req.body.countryCode, req.body.phoneNumber, req.body.client_id)
    ])
    .then(results => {
        temporaryUserId = results[1].userId;
        return EmailOtp.save(results[1].userId,results[0].eOTP,'registration',req.body.service,1)
    })
    .then(otpId => {
        cn.sendResponse(res,
            {
                temporaryUserId: temporaryUserId,
                action: 'registration',
                otpId: otpId,
                email: cn.hideEmailAddress(req.body.email.toLowerCase())
            },
            "OTP sent to email address, will be valid for the next 1 hour",200,null, 200
        )
    })
    .catch(err => {
        console.log(err);
        if(err.message == "Database server error") cn.sendResponse(res,null,"User registration details addition failed", 503, "database_server_error", 503);
        else cn.sendResponse(res,null,"User registration details addition failed", 500, "internal_server_error", 500);
    })
}

exports.userLoginDetails = (req, res, next) => {
    //---------------------------------------------
    // @VALIDATIONS
    // 1) Is the client valid -> req.body.client_id
    // 2) Login form fields validation
    // 3) Does username field contain a username or an email address -> ADD req.isEmail = true if its and email and false if its a username
    // 3) Email provided is a registered email address OR 
    // provided username is a registered username and add userId to request -> req.userId should be set to user's id to whom the email belongs
    //--------------------------------------------- 
    if(req.isEmail){
        otpServices.sendEmailOTP(req.body.username.toLowerCase())
        .then(result => EmailOtp.save(req.userId,result.eOTP,'login',req.body.service,1))
        .then(otpId => {
            cn.sendResponse(res,
                {
                    userId: req.userId,
                    action: 'login',
                    otpId: otpId,
                    email: cn.hideEmailAddress(req.body.username.toLowerCase())
                },
                "OTP sent to email address, will be valid for the next 1 hour",200,null, 200
            )
        })
    }else{
        let email;
        User.findEmail(req.userId)
        .then(result => {
            email = result;
            return otpServices.sendEmailOTP(result)
        })
        .then(result => EmailOtp.save(req.userId,result.eOTP,'login',req.body.service,1))
        .then(otpId => {
            cn.sendResponse(res,
                {
                    userId: req.userId,
                    action: 'login',
                    otpId: otpId,
                    email: cn.hideEmailAddress(email)
                },
                "OTP sent to email address, will be valid for the next 1 hour",200,null, 200
            )
        })
    }
}

exports.resendEmailOTP = (req, res, next) => {
    //---------------------------------------------
    // @VALIDATIONS
    // 1) Is the client valid -> req.body.client_id
    // 2) Resend otp form validation
    // 3) Does otpId exist
    //--------------------------------------------- 
    let otpData;
    let email;
    EmailOtp.findOneById(req.body.otpId)
    .then(result => {
        otpData = result;
        return User.findEmail(result.userId);
    })
    .then(result => {
        email = result;
        return otpServices.sendEmailOTP(result)
    })
    .then(result => EmailOtp.save(otpData.userId,result.eOTP,otpData.action,otpData.service,otpData.attemptNumber+1))
    .then(otpId => {
        if(otpData.action == "registration"){
            cn.sendResponse(res,
                {
                    temporaryUserId: otpData.userId,
                    action: otpData.action,
                    otpId: otpId,
                    email: cn.hideEmailAddress(email)
                },
                "OTP sent to email address, will be valid for the next 1 hour",200,null, 200
            )
        }else{
            cn.sendResponse(res,
                {
                    userId: otpData.userId,
                    action: otpData.action,
                    otpId: otpId,
                    email: cn.hideEmailAddress(email)
                },
                "OTP sent to email address, will be valid for the next 1 hour",200,null, 200
            )
        }
    })
}

// router.post('/userRegistrationDetails',validationMiddleware, authController.userRegistrationDetails);
// router.post('/userLoginDetails',validationMiddleware,authController.userLoginDetails);
// router.post('/resendEmailOTP',validationMiddleware,authController.resendEmailOTP);
// router.post('/mobileOTPLogin',validationMiddleware,authController.mobileOTPLogin);
// router.post('/resendPhoneOTP',validationMiddleware, authController.resendPhoneOTP);

// router.post('/resetPasswordEmail',validationMiddleware, authController.resetPasswordEmail);

// router.post('/setNewPassword',validationMiddleware, authController.setNewPassword);
