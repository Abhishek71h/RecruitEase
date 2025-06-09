import adminSchema from "../model/adminSchema.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import recruiterSchema from "../model/recruiterSchema.js";
import candidateSchema from "../model/candidateSchema.js";
import appliedVacancySchema from "../model/appliedVacancySchema.js";
import VacancySchema from '../model/vacancySchema.js';

dotenv.config();

var admin_secret_key = process.env.ADMIN_SECRET_KEY;
//console.log("admin_secret_key : ",typeof admin_secret_key);

export const adminLoginController = async(request,response)=>{
    try{
         //console.log("admin Email : ",request.body.email);
         
         const adminObj = await adminSchema.findOne({email:request.body.email});
         const adminPassword = adminObj.password;
         const status = await bcrypt.compare(request.body.password,adminPassword);
         if(status){
            const expireTime = {expiresIn:'1d'};
            const token = jwt.sign({email:request.body.email},admin_secret_key,expireTime);
            //console.log("Token : ",token);
            
            if(!token)
            {
                response.render("adminLogin",{message:"Error while setting up the token while admin login"});
            }
                

            response.cookie('admin_jwt_token',token,{maxAge:24*60*60*1000,httpOnly:true});
            response.render("adminHome",{email:request.body.email});
            //response.status(200).send({status:true,email:request.body.email,token:token});
         }     
        else{
            response.render("adminLogin",{message:"Email Id or Password is Wrong"}); 
            //response.status(203).send({status:false,message:"Email Id or Password is Wrong"});
        }
    }catch(error){
        console.log("Error in adminLogin : ",error);
        response.render("adminLogin",{message:"Something Went Wrong"}); 
        //response.status(500).send({status:false,message:"Something Went Wrong"});
    }
}

export const adminLogoutController = async(request,response)=>{
    //console.log(response);
    response.clearCookie('admin_jwt_token');
    response.render("adminLogin",{message:"Admin Logout Successfully"});    
}

export const adminRecruiterListController = async(request,response)=>{
    try{
        const recruiterList = await recruiterSchema.find();
        response.render("adminRecruiterList",{email:request.payload.email,recruiterList:recruiterList,message:""});
        //response.status(200).send({email:request.payload.email,recruiterList:recruiterList,message:""});
    }catch(error){
        console.log("Error at adminRecruiterListController");
        response.render("adminHome",{email:request.payload.email});
        //response.status(500).send({email:request.payload.email});
    }
}

export const adminVerifyRecruiterController = async(request,response)=>{
    try{
        const recruiterEmail = request.query.recruiterEmail;
        const updateStatus = {
            $set : {
                adminVerify:"Verified"
            }
        }
        const updateResult = await recruiterSchema.updateOne({email:recruiterEmail},updateStatus);
        //console.log("Update Result : ",updateResult);
        
        const recruiterList = await recruiterSchema.find();
        response.render("adminRecruiterList",{email:request.payload.email,recruiterList:recruiterList,message:recruiterEmail+" Verified Successfully"});
        console.log("-------> ",recruiterList);
        
     response.status(200).send({email:request.payload.email,recruiterList:recruiterList,message:recruiterEmail+" Verified Successfully"});
    }catch(error){
        console.log("Error in adminVerifyRecruiterController : ",error);    
        const recruiterList = await recruiterSchema.find();
        response.render("adminRecruiterList",{email:request.payload.email,recruiterList:recruiterList,message:"Error While Updating Recruiter"});
        //response.status(500).send({email:request.payload.email,recruiterList:recruiterList,message:"Error While Updating Recruiter"});
    }
}


export const adminCandidateListController = async(request, response) => {
    try {
        const candidateList = await candidateSchema.find();
        response.render("adminCandidateList", {
            email: request.payload.email,
            candidateList: candidateList,
            message: ""
        });
        // response.status(200).send({ email: request.payload.email, candidateList: candidateList, message: "" });
    } catch (error) {
        console.log("Error at adminCandidateListController");
        response.render("adminHome", { email: request.payload.email });
        // response.status(500).send({ email: request.payload.email });
    }
}



export const adminVerifyCandidateController = async(request,response)=>{
    try{
        const candidateEmail = request.query.candidateEmail;
        const updateStatus = {
            $set : {
                adminVerify:"Verified"
            }
        }
        const updateResult = await candidateSchema.updateOne({_id: candidateEmail}, updateStatus);
        //console.log("Update Result : ", updateResult);
        
        const candidateList = await candidateSchema.find();
        response.render("adminCandidateList", {
            email: request.payload.email,
            candidateList: candidateList,
            message: candidateEmail + " Verified Successfully"
        });

        // response.status(200).send({ email: request.payload.email, candidateList: candidateList, message: candidateEmail + " Verified Successfully" });
    } catch(error){
        console.log("Error in adminVerifyCandidateController : ", error);    
        const candidateList = await candidateSchema.find();
        response.render("adminCandidateList", {
            email: request.payload.email,
            candidateList: candidateList,
            message: "Error While Updating Candidate"
        });
        // response.status(500).send({ email: request.payload.email, candidateList: candidateList, message: "Error While Updating Candidate" });
    }
}



export const adminApplyCandidateListController = async (request, response) => {
    try {
        const appliedVacancyList = await appliedVacancySchema.find();

        let result = [];
        for (let i = 0; i < appliedVacancyList.length; i++) {
            let candidateObj = await candidateSchema.findOne({ _id: appliedVacancyList[i].candidateEmail });
            result.push(candidateObj?.docs); 
        }

        let message = appliedVacancyList.length === 0 ? "No Record Found" : "";

        response.render("adminAppliedCandidateList", {
            email: request.payload.email,
            appliedVacancyList,
            result,
            message
        });
    } catch (error) {
        console.log("Error in adminAppliedCandidateListController:", error);
        response.render("adminAppliedCandidateList", {
            email: request.payload.email,
            appliedVacancyList: [],
            result: [],
            message: "Error While Fetching Data"
        });
    }
};



export const adminVacancyListController = async (request, response) => {
    try {
        const vacancies = await VacancySchema.find();

        let message = vacancies.length === 0 ? "No Vacancies Found" : "";

        response.render("adminVacancyList", {
            email: request.payload.email,
            vacancies: vacancies,
            message: message
        });
    } catch (error) {
        console.log("Error fetching vacancies:", error);
        response.render("adminVacancyList", {
            email: request.payload.email,
            vacancies: [],
            message: "Error While Fetching Data"
        });
    }
};


