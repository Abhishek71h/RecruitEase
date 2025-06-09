import express from 'express';
import { candidateRegistrationController,candidateVerifyEmailController,candidateLoginController,candidateLogoutController,candidateVacancyListController,myStatusController, forgotPasswordFormController,  sendResetLinkController,showResetPasswordFormController,  resetPasswordController, handleChat } from '../controller/candidateController.js';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
dotenv.config();
const candidate_secret_key = process.env.CANDIDATE_SECRET_KEY;

var candidateRouter = express.Router();

candidateRouter.use(express.static('public'));
let authenticateJWT = (request,response,next)=>{
    //console.log("gets entry");
     const token = request.cookies.candidate_jwt_token;
    //const token = request.query.candidateToken;
    //console.log("token : ",token);
    try{  
        jwt.verify(token,candidate_secret_key,(error,payload)=>{
            if(error){
                response.render("candidateLogin",{message:"Please Login First"});
            }else{
                request.payload=payload;
                next();
            }
        });
    }catch(error){
        response.render("candidateLogin",{message:"Something went wrong in JWT"});
    }
}

candidateRouter.get("/candidateLogin", (req, res) => {
    // Get the message from the query parameter if it's present
    const message = req.query.message;

    // Render the login page and pass the message
    res.render("candidateLogin.ejs", { message: message });
});

candidateRouter.get("/candidateLogout",candidateLogoutController);

candidateRouter.get("/candidateRegistration",(request,response)=>{
    response.render("candidateRegistration.ejs");
});
candidateRouter.post("/candidateRegistration",candidateRegistrationController);
candidateRouter.get("/verifyEmail",candidateVerifyEmailController);
candidateRouter.post("/candidateLogin",candidateLoginController);

candidateRouter.get("/candidateHome",authenticateJWT,(request,response)=>{
    response.render("candidateHome.ejs",{email:request.payload.email});
});

candidateRouter.get("/vacancyList",authenticateJWT,candidateVacancyListController);
candidateRouter.get("/myStatus",authenticateJWT,myStatusController);


candidateRouter.get('/forgotPassword', forgotPasswordFormController); 
candidateRouter.post('/forgotPassword', sendResetLinkController);     

candidateRouter.get('/resetPassword/:token', showResetPasswordFormController);
candidateRouter.post('/resetPassword/:token', resetPasswordController);

candidateRouter.post('/chatbot', handleChat);

export default candidateRouter;