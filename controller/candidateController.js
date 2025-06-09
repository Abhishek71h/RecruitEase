import mailer from "../router/mailer.js"
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';
import path from 'path';
import candidateSchema from "../model/candidateSchema.js";
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import vacancySchema from "../model/vacancySchema.js";
import appliedVacancySchema from "../model/appliedVacancySchema.js";
import fetch from 'node-fetch'; 

dotenv.config();
var candidate_secret_key = process.env.CANDIDATE_SECRET_KEY;

export const candidateRegistrationController = async (request, response) => {
    try {
        //console.log("candidate file data : ",request.files);
        
        const __filename = fileURLToPath(import.meta.url);
        //console.log("__filename : ",__filename);
        const __dirname = path.dirname(__filename).replace("\\controller", "");
        //console.log("__dirname : ",__dirname);
        //console.log("request.files : ",request.files);
        const filename = request.files.docs;
        const fileName = new Date().getTime() + filename.name;
        const pathName = path.join(__dirname, "/public/documents/", fileName);
        //console.log("pathName : ",pathName);

        filename.mv(pathName, async (error) => {
            if (error) {
                console.log("Error occured while uploading file");
            } else {
                console.log("File uploaded successfully");
                const { name, _id, password, gender, dob, address, contact, qualification, percentage, experience } = request.body;
                const obj = {
                    name: name,
                    _id: _id,
                    password: await bcrypt.hash(password, 10),
                    gender: gender,
                    dob: dob,
                    address: address,
                    contact: contact,
                    qualification: qualification,
                    percentage: percentage,
                    experience: experience,
                    docs:fileName
                }
                const mailContent = `Hello ${_id},<br>This is a verification mail by RecruitEase. You Needs to verify yourself by clicking on the below link.<br><a href='http://localhost:3000/candidate/verifyEmail?email=${_id}'>Click Here To Verify</a>`;

                mailer.mailer(mailContent, _id, async (info) => {
                    if (info) {
                        const result = await candidateSchema.create(obj);
                        //console.log("Result of candidate registration : ", result);
                        response.render("candidateLogin", { message: "Email Sent | Please Verify" });

                    } else {
                        console.log("Error while sending email");
                        response.render("candidateRegistration", { message: "Error while sending email" });
                    }
                })
            }
        });

    } catch (error) {
        //console.log("Error occured in candidate registration uploading file : ", error);
        response.render("recruiterRegistration.ejs",{message : "Error occured in recruiter registration"});
    }
}

export const candidateVerifyEmailController = async(request,response)=>{
    const email = request.query.email;
    const updateStatus = {$set:{emailVerify:"Verified"}};
    const updateResult = await candidateSchema.updateOne({_id:email},updateStatus);
    //console.log("Update Result : ",updateResult);
    response.render("candidateLogin",{message:"Email Verified | Admin verification takes 24 Hours"});
}

export const candidateLoginController = async(request,response)=>{
    try{
         //console.log("gets entry in candidate login controller");
            
         const candidateObj = await candidateSchema.findOne({_id:request.body.email});
         //console.log("-------------> ",candidateObj);
         if(candidateObj==null)
                throw new Error("Candidate not exist");   
         
         const candidatePassword = candidateObj.password;
         const candidateStatus = candidateObj.status;
         //console.log("candidateStatus : ",candidateStatus);
         //console.log("typeof candidateStatus : ",typeof candidateStatus);
         
         const adminVerifyStatus = candidateObj.adminVerify;
         const emailVerifyStatus = candidateObj.emailVerify;
         
         const status = await bcrypt.compare(request.body.password,candidatePassword);
         if(status && candidateStatus && adminVerifyStatus=="Verified" && emailVerifyStatus == "Verified"){
            const expireTime = {expiresIn:'1d'};
            const token = jwt.sign({email:request.body.email},candidate_secret_key,expireTime);
            //console.log("Token : ",token);
            
            if(!token)
                response.render("candidateLogin",{message:"Error while setting up the token while candidate login"});
                //response.status(203).send({status:false,message:"Error while setting up the token while candidate login"});

            response.cookie('candidate_jwt_token',token,{maxAge:24*60*60*1000,httpOnly:true});
            response.render("candidateHome",{email:request.body.email});
            //response.status(200).send({status:true,email:request.body.email,token:token}); 
        }     
        else
             response.render("candidateLogin",{message:"Password is Wrong || Admin may need to verfiy"}); 
            //response.status(203).send({status:false,message:"Password is Wrong"});
    }catch(error){
        console.log("Error in candidateLogin : ",error);
        response.render("candidateLogin",{message:"Candidate doesn't exist"}); 
        //response.status(500).send({status:false,message:"Something Went Wrong"});
    }
}

export const candidateLogoutController = async(request,response)=>{
    //console.log(response);
    response.clearCookie('candidate_jwt_token');
    response.render("candidateLogin",{message:"Candidate Logout Successfully"});    
}

export const candidateVacancyListController = async(request,response)=>{
    try{
        const vacancyList = await vacancySchema.find();
        //console.log("vacancyList : ",vacancyList);
        if(vacancyList.length==0){
            response.render("candidateVacancyList",{email:request.payload.email,vacancyList:vacancyList,message:"No Record Found",status:[]});
            //response.status(200).send({status:true,email:request.payload.email,vacancyList:vacancyList,message:"No Record Found",vacancyStatus:[]});
        }else{
            const candidateVacancyRecord = await appliedVacancySchema.find({candidateEmail:request.payload.email});
            
            //console.log(candidateVacancyRecord);
            if(candidateVacancyRecord.length==0){
                response.render("candidateVacancyList",{email:request.payload.email,vacancyList:vacancyList,message:"",status:[]});
                //response.status(200).send({status:true,email:request.payload.email,vacancyList:vacancyList,message:"",vacancyStatus:[]});
            }else{
                //console.log(candidateVacancyRecord);
                response.render("candidateVacancyList",{email:request.payload.email,vacancyList:vacancyList,message:"",status:candidateVacancyRecord});
                //response.status(200).send({status:true,email:request.payload.email,vacancyList:vacancyList,message:"",vacancyStatus:candidateVacancyRecord});
            }
            
        }
    }catch(error){
        console.log("Error : ",error);
        const vacancyList = await vacancySchema.find();
        response.render("candidateVacancyList",{email:request.payload.email,vacancyList:vacancyList,message:"Wait Data is Loading",status:false});
        //response.status(500).send({status:false,email:request.payload.email,vacancyList:vacancyList,message:"Wait Data is Loading",vacancyStatus:false});
    }
}

export const myStatusController = async(request,response)=>{
    try{
        const appliedVacancyList = await appliedVacancySchema.find({candidateEmail:request.payload.email});
        //console.log("Applied VacancyList : ",appliedVacancyList);
        if(appliedVacancyList.length==0){
            response.render("myStatusList",{email:request.payload.email,appliedVacancyList:appliedVacancyList,message:"No Record Found"});
            //response.status(200).send({status:true,email:request.payload.email,appliedVacancyList:appliedVacancyList,message:"No Record Found"});
        }else{
            response.render("myStatusList",{email:request.payload.email,appliedVacancyList:appliedVacancyList,message:""});
            //response.status(200).send({status:true,email:request.payload.email,appliedVacancyList:appliedVacancyList,message:""});
        }
    }catch(error){
        console.log("Error in myStatusController : ",error);
        const appliedVacancyList = await appliedVacancySchema.find({candidateEmail:request.payload.email});
        response.render("myStatusList",{email:request.payload.email,appliedVacancyList:appliedVacancyList,message:"Wait Data is Loading"});
        //response.status(500).send({status:false,email:request.payload.email,appliedVacancyList:appliedVacancyList,message:"Wait Data is Loading"});
    }
}


// Render forgot password page
export const forgotPasswordFormController = async (req, res) => {
    //console.log("GET /candidate/forgotPassword route hit");
    res.render('candidateForgotPassword');
};


export const sendResetLinkController = async (req, res) => {
    const { email } = req.body;

    try {
        const candidate = await candidateSchema.findOne({ _id: email });
        if (!candidate) {
            return res.render('candidateForgotPassword', { message: 'User not found. Please try again.' });
        }

        const token = jwt.sign({ email: candidate._id }, candidate_secret_key, { expiresIn: '1h' });

        const resetLink = `http://localhost:3000/candidate/resetPassword/${token}`;

        const mailContent = `
            <h2>Reset Your Password</h2>
            <p>Click the following link to reset your password:</p>
            <a href="${resetLink}">Reset Password</a>
        `;

        mailer.mailer(mailContent, email, (info) => {
            res.render('candidateForgotPassword', { message: 'Reset link sent to your email. Please check your inbox.' });
        });
        
    } catch (error) {
        console.log("Error in sending reset link:", error);
        res.render('candidateForgotPassword', { message: 'An error occurred. Please try again.' });
    }
};


export const showResetPasswordFormController = (req, res) => {
    const { token } = req.params;
    res.render('candidateResetPassword', { token });
};



export const resetPasswordController = async (req, res) => {
    const { token } = req.params;
    const { oldPassword, newPassword, confirmPassword } = req.body;

    try {
        const decoded = jwt.verify(token, candidate_secret_key);
        const email = decoded.email;

        const candidate = await candidateSchema.findOne({ _id: email });
        if (!candidate) {
            return res.render('candidateResetPassword', { token, message: 'Invalid token or user not found.' });
        }

        const isMatch = await bcrypt.compare(oldPassword, candidate.password);
        if (!isMatch) {
            return res.render('candidateResetPassword', { token, message: 'Old password is incorrect.' });
        }

        if (newPassword !== confirmPassword) {
            return res.render('candidateResetPassword', { token, message: 'New and confirm passwords do not match.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        candidate.password = hashedPassword;

        // Optionally, delete the reset token (if it was stored in the database)
        // candidate.resetToken = null; // Assuming you're storing reset token in the DB, remove it
        await candidate.save();

        // Clear the token from the cookies if it was stored there
        res.clearCookie('resetToken'); // If the token was stored in cookies

        // Redirect to the candidate login page with a success message
        res.redirect('/candidate/candidateLogin?message=Password+successfully+updated.+Please+login+with+new+credentials.');
    } catch (error) {
        console.log("Error in resetting password:", error);
        res.render('candidateResetPassword', { token, message: 'Something went wrong. Please try again.' });
    }
};



export const handleChat = async (req, res) => {
  const userMessage = req.body.message;

  try {
    // Making a request to Ollama's local API
    const ollamaRes = await fetch("http://127.0.0.1:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama2", // Replace with the model you want to use (e.g., llama2, or another model)
        prompt: userMessage, // Send the user’s message as the prompt
        stream: false, // Set to false to get the full response
      }),
    });

    // Parse the response from Ollama
    const data = await ollamaRes.json();

    if (!ollamaRes.ok) {
      throw new Error('Failed to communicate with Ollama');
    }

    const aiReply = data.response.trim(); // Get the AI reply from the response data
    res.json({ reply: aiReply });

  } catch (err) {
    console.error("Error with Ollama:", err);
    res.status(500).json({ error: 'Error communicating with Ollama' });
  }
};
