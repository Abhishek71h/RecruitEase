import express from 'express';
import { recruiterRegistrationController,recruiterVerifyEmailController,recruiterLoginController,recruiterVacancyPostedController,recruiterLogoutController,appliedCandidateListController,recruiterUpdateStatusController, sendResetLinkController, resetPasswordController,  handleRecruiterChat} from '../controller/recruiterController.js';
import jwt from 'jsonwebtoken';
import recruiterSchema from '../model/recruiterSchema.js';
import dotenv from 'dotenv';
dotenv.config();
const recruiter_secret_key = process.env.RECRUITER_SECRET_KEY;
var recruiterRouter = express.Router();
recruiterRouter.use(express.static('public'));

let authenticateJWT = (request,response,next)=>{
    //console.log("gets entry");
    const token = request.cookies.recruiter_jwt_token;
    //const token = request.query.recruiterToken;
    //console.log("token : ",token);
    try{  
        jwt.verify(token,recruiter_secret_key,(error,payload)=>{
            if(error){
                response.render("recruiterLogin",{message:"Please Login First"});
            }else{
                request.payload=payload;
                next();
            }
        });
    }catch(error){
        response.render("recruiterLogin",{message:"Something went wrong in JWT"});
    }
}

recruiterRouter.get("/recruiterLogin", (req, res) => {
    res.render("recruiterLogin", {
        message: req.query.message || ""
    });
});


recruiterRouter.get("/recruiterLogout",recruiterLogoutController);

recruiterRouter.get("/recruiterRegistration",(request,response)=>{
    response.render("recruiterRegistration.ejs",{message:""});
});

recruiterRouter.post("/recruiterRegistration",recruiterRegistrationController);
recruiterRouter.get("/verifyEmail",recruiterVerifyEmailController);
recruiterRouter.post("/recruiterLogin",recruiterLoginController);

recruiterRouter.get("/recruiterHome",authenticateJWT,(request,response)=>{
    response.render("recruiterHome.ejs",{email:request.payload.email});
});

recruiterRouter.get("/addVacancy",authenticateJWT,async(request,response)=>{
    const recruiterObj = await recruiterSchema.findOne({email:request.payload.email});
    console.log("recruiterObj : ",recruiterObj);
    response.render("addVacancy.ejs",{email:request.payload.email,recruiterObj:recruiterObj,message:""});
});

recruiterRouter.get("/vacancyPosted",authenticateJWT,recruiterVacancyPostedController);
recruiterRouter.get("/appliedCandidateList",authenticateJWT,appliedCandidateListController);
recruiterRouter.post("/recruiterUpdateStatus",authenticateJWT,recruiterUpdateStatusController);


recruiterRouter.get("/forgotPassword", (req, res) => {
    res.render("recruiterForgotPassword", { message: "" });
}); 

recruiterRouter.post("/forgotPassword", sendResetLinkController);

recruiterRouter.get('/resetPassword/:token', (req, res) => {
    const token = req.params.token;

    res.render('recruiterResetPassword', { token: token, message: "" });
});

recruiterRouter.post('/resetPassword/:token', resetPasswordController);

recruiterRouter.post('/chatbot', handleRecruiterChat);



export default recruiterRouter;