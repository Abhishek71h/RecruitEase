import express from 'express';
import jwt from 'jsonwebtoken';
import { candidateAppliedVacancyController } from '../controller/appliedVacancyController.js';
import dotenv from 'dotenv';
dotenv.config();

var appliedVacancyRouter = express.Router();
const candidate_secret_key = process.env.CANDIDATE_SECRET_KEY;
appliedVacancyRouter.use(express.static('public'));

let authenticateJWT = (request,response,next)=>{
     const token = request.cookies.candidate_jwt_token;
    //const token = request.query.candidateToken;
    try{  
        jwt.verify(token,candidate_secret_key,(error,payload)=>{
            if(error){
                response.render("candidateLogin",{message:"Please Login First"});
                //response.status(203).send({message:"Please Login First"});
            }else{
                request.payload=payload;
                next();
            }
        });
    }catch(error){
        console.log("Error : ",error);
        response.render("candidateLogin",{message:"Something went wrong in JWT"});
        //response.status(500).send({message:"Something went wrong in JWT"});
    }
}

appliedVacancyRouter.get("/candidateAppliedVacancy",authenticateJWT, candidateAppliedVacancyController);

export default appliedVacancyRouter;