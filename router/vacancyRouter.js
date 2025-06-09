import express from 'express';
import jwt from 'jsonwebtoken';
import { recruiterAddVacancyController } from '../controller/vacancyController.js';
import dotenv from 'dotenv';
dotenv.config();

var vacancyRouter = express.Router();
vacancyRouter.use(express.static('public'));
const recruiter_secret_key = process.env.RECRUITER_SECRET_KEY;

let authenticateJWT = (request,response,next)=>{
    console.log("gets entry in add vacancy");
    const token = request.cookies.recruiter_jwt_token;
    //const token = request.query.recruiterToken;
    
    //console.log("token in add vacancy: ",token);
    try{  
        jwt.verify(token,recruiter_secret_key,(error,payload)=>{
            if(error){
                response.render("recruiterLogin",{message:"Please Login First"});
                //response.status(203).send({message:"Please Login First"});
            }else{
                request.payload=payload;
                next();
            }
        });
    }catch(error){
        console.log("Error : ",error);
        
        response.render("recruiterLogin",{message:"Something went wrong in JWT"});
        //response.status(500).send({message:"Something went wrong in JWT"});
    }
}

vacancyRouter.post("/addVacancy",authenticateJWT,recruiterAddVacancyController);

export default vacancyRouter;