import express from 'express';
import { adminLoginController,adminLogoutController,adminRecruiterListController,adminVerifyRecruiterController , adminCandidateListController, adminVerifyCandidateController, adminVacancyListController, adminApplyCandidateListController} from '../controller/adminController.js';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();
const admin_secret_key = process.env.ADMIN_SECRET_KEY;
var adminRouter = express.Router();
adminRouter.use(express.static('public'));

let authenticateJWT = (request,response,next)=>{
   // console.log("gets entry");
    const token = request.cookies.admin_jwt_token;
    //const token = request.query.adminToken;
    //console.log("token : ",token);
    try{
        
        jwt.verify(token,admin_secret_key,(error,payload)=>{
            if(error){
                response.render("adminLogin",{message:"Please Login First"});
            }else{
                request.payload=payload;
                next();
            }
        });
    }catch(error){
        response.render("adminLogin",{message:"Something went wrong in JWT"});
    }
}

adminRouter.get("/",(request,response)=>{
    response.render("adminLogin.ejs",{message:""});
});

adminRouter.post("/adminLogin",adminLoginController);
adminRouter.get("/adminLogout",adminLogoutController);

adminRouter.get("/adminHome",authenticateJWT,(request,response)=>{
    response.render("adminHome.ejs",{email:request.payload.email});
});

adminRouter.get("/adminRecruiterList",authenticateJWT, adminRecruiterListController);
adminRouter.get('/adminCandidateList', authenticateJWT, adminCandidateListController);

adminRouter.get("/adminVerifyRecruiter",authenticateJWT,adminVerifyRecruiterController);
adminRouter.get("/adminVerifyCandidate", authenticateJWT, adminVerifyCandidateController);

adminRouter.get("/adminVacancyList", authenticateJWT, adminVacancyListController);
adminRouter.get("/adminApplyCandidateList", authenticateJWT, adminApplyCandidateListController);
export default adminRouter;