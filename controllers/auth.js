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
 * 23/10/2021 - PS - Refactored
 *
 *  
 * TODO: Add a cron job that deletes all the invalidated or used up otps from DB if they are not required for analytics purpose
 * IMPORTANT - 
**/
const bcrypt = requie('bcrypt');
const cn = require('../utils/common');

//Models
const User = require('../models/user');
const TemporaryUser = require('../models/temporaryUser');
const Otp = require('../models/otp');
const EmailOtp = require('../models/emailOtp');
const RecoveryToken = require('../models/recoveryToken');

//Services
const emailService = require('../services/emailOtp');
const messagingService = require('../services/otpServices');
const generateService = require('../services/generate');
const jweService = require('../services/jwe');

exports.userRegistrationDetails = (req, res, next) => {
/**
 * @Validations
 * 1) Is the client valid -> req.body.client_id
 * 2) Registration form fields validation
 * 3) Does Email already exist(DB action - User model needed)
**/
    let temporaryUserId;   
    bcrypt.hash(req.body.password, saltRounds)
    .then(hashedPassword => {
        const temporaryUser = new TemporaryUser(req.body.firstName, req.body.lastName, req.body.email.toLowerCase(), hashedPassword, req.body.countryCode, req.body.phoneNumber, req.body.client_id);
        return Promise.all([
            emailService.sendOTP(req.body.email.toLowerCase()),
            temporaryUser.save()
        ])
    })
    .then(results => {
        temporaryUserId = results[1].userId;
        const emailOTP = new EmailOtp(req.userId,results[0].eOTP,'login',req.body.service,1);
        return emailOTP.save();
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
/**
 * @Validations
 * 1) Is the client valid -> req.body.client_id
 * 2) Login form fields validation
 * 3) Does username field contain a username or an email address -> ADD req.isEmail = true if its and email and false if its a username
 * 4) Email provided is a registered email address OR 
 *    provided username is a registered username and add userId to 
 *    request -> req.userId should be set to user's id to whom the email belongs(Or adding userId to req could be done using a middleware)
**/
    if(req.isEmail){
        emailService.sendOTP(req.body.username.toLowerCase())
        .then(result => {
            const emailOTP = new EmailOtp(req.userId,result.eOTP,'login',req.body.service,1);
            return emailOTP.save();
        })
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
        .catch(err => {
            console.log(err);
            if(err.message == "Database server error") cn.sendResponse(res,null,"User registration details addition failed", 503, "database_server_error", 503);
            else cn.sendResponse(res,null,"User registration details addition failed", 500, "internal_server_error", 500);
        })
    }else{
        let email;
        User.findEmail(req.userId)
        .then(result => {
            email = result;
            return emailService.sendOTP(result)
        })
        .then(result => {
            const emailOTP = new EmailOtp(req.userId,result.eOTP,'login',req.body.service,1);
            return emailOTP.save();
        })
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
        .catch(err => {
            console.log(err);
            if(err.message == "Database server error") cn.sendResponse(res,null,"User login details check failed", 503, "database_server_error", 503);
            else cn.sendResponse(res,null,"User login details check failed", 500, "internal_server_error", 500);
        })
    }
}

exports.resendEmailOTP = (req, res, next) => {
/**
 * @Validations
 * 1) Is the client valid -> req.body.client_id
 * 2) Resend otp form validation
 * 3) Does otpId exist
**/
    let otpData;
    let email;
    EmailOtp.findOneById(req.body.otpId)
    .then(result => {
        otpData = result;
        return User.findEmail(result.userId);
    })
    .then(result => {
        email = result;
        return emailService.sendOTP(result)
    })
    .then(result => {
        const emailOTP = new EmailOtp(otpData.userId,result.eOTP,otpData.action,otpData.service,otpData.attemptNumber+1);
        return emailOTP.save();
    })
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
    .catch(err => {
        console.log(err);
        if(err.message == "Database server error") cn.sendResponse(res,null,"Resend Email OTP Failed", 503, "database_server_error", 503);
        else cn.sendResponse(res,null,"Resend Email OTP Failed", 500, "internal_server_error", 500);
    })
}

exports.mobileOTPLogin = (req, res, next) => {
/**
 *  @Validations
 * 1) Is the client valid -> req.body.client_id
 * 2) Mobiel otp login form validation
 * 3) Email provided is a registered email address OR 
 *    provided username is a registered username and add userId to 
 *    request -> req.userId should be set to user's id to whom the email belongs(Or adding userId to req could be done using a middleware)
**/
    let phoneNumber;
    let countryCode;
    //Need to find phone number, its country code and whether its verified or not first because during phone number login we receive email 
    //or username in request body not phone number
    User.findPhoneNumber(req.userId)  
    .then(result => {
        phoneNumber = result.phoneNumber;
        countryCode = result.countryCode;
        if(result.verified) return messagingService.sendOTP(result.phoneNumber)  //If phone is verified only then it can be used for login
        else {
            cn.sendResponse(res,null,"Mobile otp login process failed", 459, "phone_not_verified", 401);
        }
    })
    .then(result => {
        const otp = new Otp(req.userId,result.mOTP,'login',req.body.service,1);
        return otp.save();
    })
    .then(otpId => {
        cn.sendResponse(res,
            {
                userId: req.userId,
                action: 'login',
                otpId: otpId,
                countryCode: countryCode,
                phoneNumber: cn.hidePhoneNumber(phoneNumber)
            },
            "OTP sent to phone number, will be valid for the next 1 hour",200,null, 200
        )
    })
    .catch(err => {
        console.log(err);
        if(err.message == "Database server error") cn.sendResponse(res,null,"Mobile otp login process failed", 503, "database_server_error", 503);
        else cn.sendResponse(res,null,"Mobile otp login process failed", 500, "internal_server_error", 500);
    })
}

exports.resendPhoneOTP = (req, res, next) => {
/**
 * @Validations
 * 1) Is the client valid -> req.body.client_id
 * 2) Resend otp form validation
 * 3) Does otpId exist
**/
    let otpData;
    let phoneNumber;
    Otp.findOneById(req.body.otpId)
    .then(result => {
        otpData = result;
        return User.findPhoneNumber(result.userId);
    })
    .then(result => {
        phoneNumber = result.phoneNumber;
        countryCode = result.countryCode;
        return messagingService.sendOTP(result)
    })
    .then(result => {
        const otp = new Otp(otpData.userId,result.mOTP,otpData.action,otpData.service,otpData.attemptNumber+1);
        return otp.save();
    })
    .then(otpId => {
        cn.sendResponse(res,
            {
                userId: otpData.userId,
                action: otpData.action,
                otpId: otpId,
                countryCode: countryCode,
                phoneNumber: cn.hideEmailAddress(phoneNumber)
            },
            "OTP sent to phone number, will be valid for the next 1 hour",200,null, 200
        )
    })
    .catch(err => {
        console.log(err);
        if(err.message == "Database server error") cn.sendResponse(res,null,"Resend Phone OTP Failed", 503, "database_server_error", 503);
        else cn.sendResponse(res,null,"Resend Phone OTP Failed", 500, "internal_server_error", 500);
    })
}

exports.resetPasswordEmail = (req, res, next) => {
/**
 * @Validations
 * 1) Is the client valid -> req.body.client_id
 * 2) Resen password email form validation
 * 3) Does username field contain a username or an email address -> ADD req.isEmail = true if its and email and false if its a username
 * 4) Email provided is a registered email address OR 
 *    provided username is a registered username and add userId to 
 *    request -> req.userId should be set to user's id to whom the email belongs(Or adding userId to req could be done using a middleware)
**/
    if(req.isEmail){
        generateService.generateGivenByteSizeString(16)
        .then(result => {
            let expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + 1);
            const recoveryToken = new RecoveryToken(result, req.userId, expiryDate)
            return recoveryToken.save();
        })
        .then(result => jweService.createEncrypt(process.env.RECOVERYTOKENENCRYPTIONKEY,token))  //createEncrypt takes the key as first parameter and data to be encrypted as second parameter
        .then(JWE => emailService.sendRecoveryEmail(req.body.username,JWE))
        .then(result => sendResponse(res,null,"Reset password email process completed - Email has been sent to registered email address", 200, null, 200))
        .catch(err => {
            console.log(err);
            if(err.message == "Database server error") cn.sendResponse(res,null,"Resend Phone OTP Failed", 503, "database_server_error", 503);
            else cn.sendResponse(res,null,"Resend Phone OTP Failed", 500, "internal_server_error", 500);
        })
    }else{
        generateService.generateGivenByteSizeString(16)
        .then(result => {
            let expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + 1);
            const recoveryToken = new RecoveryToken(result, req.userId, expiryDate)
            return recoveryToken.save();
        })
        .then(result => Promise.all(
            [
                jweService.createEncrypt(process.env.RECOVERYTOKENENCRYPTIONKEY,token),
                User.findEmail(req.userId)
            ])
        )  //createEncrypt takes the key as first parameter and data to be encrypted as second parameter
        .then(results => emailService.sendRecoveryEmail(results[1],results[0]))
        .then(result => sendResponse(res,null,"Reset password email process completed - Email has been sent to registered email address", 200, null, 200))
        .catch(err => {
            console.log(err);
            if(err.message == "Database server error") cn.sendResponse(res,null,"Resend Phone OTP Failed", 503, "database_server_error", 503);
            else cn.sendResponse(res,null,"Resend Phone OTP Failed", 500, "internal_server_error", 500);
        })
    }
}

exports.setNewPassword = (req, res, next) => {
/**
 * @Validations
 * 1) Is the client valid -> req.body.client_id
 * 2) Set password form validation
 * 3) Does recovery token exist, if exists set req.tokenId = <Recovery Token's Id>, req.userId = userId in the token
**/
    RecoveryToken.findById(req.tokenId)
    .then(result => {
        if(!result.expired) cn.sendResponse(res,null,"Recovery token expired", 410, "gone", 410);
        else return crypt.hash(myPlaintextPassword, 12);
    })
    .then(hashedPassword => {
        const user = new User(req.userId, null, null, null, null, null, hashedPassword, null, null, null, null, null, null, null, Date.now());
        return user.update();
    })
    .then(result => sendResponse(res,null,"Password reset successful",200,null, 200))
    .catch(err => {
        console.log(err);
        if(err.message == "Database server error") cn.sendResponse(res,null,"Resend Phone OTP Failed", 503, "database_server_error", 503);
        else cn.sendResponse(res,null,"Resend Phone OTP Failed", 500, "internal_server_error", 500);
    })
}