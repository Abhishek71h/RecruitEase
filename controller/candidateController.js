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
        const __filename = fileURLToPath(import.meta.url);
        const __dirname = path.dirname(__filename).replace("\\controller", "");
        const filename = request.files.docs;
        const fileName = new Date().getTime() + filename.name;
        const pathName = path.join(__dirname, "/public/documents/", fileName);

        filename.mv(pathName, async (error) => {
            if (error) {
                console.log("Error occurred while uploading file");
                return response.render("candidateRegistration", { message: "File upload failed" });
            }

            const { name, _id, password, gender, dob, address, contact, qualification, percentage, experience } = request.body;

            const obj = {
                name,
                _id,
                password: await bcrypt.hash(password, 10),
                gender,
                dob,
                address,
                contact,
                qualification,
                percentage,
                experience,
                docs: fileName,
                emailVerify: "Verified"  // Email verified by default
            };

            await candidateSchema.create(obj);
            response.render("candidateLogin", { message: "Registered successfully. Waiting for Admin Approval." });
        });

    } catch (error) {
        console.log("Error occurred in candidate registration:", error);
        response.render("candidateRegistration", { message: "Registration failed. Please try again." });
    }
}

export const candidateVerifyEmailController = async(request,response)=>{
    const email = request.query.email;
    const updateStatus = {$set:{emailVerify:"Verified"}};
    const updateResult = await candidateSchema.updateOne({_id:email},updateStatus);
    //console.log("Update Result : ",updateResult);
    response.render("candidateLogin",{message:"Email Verified | Admin verification takes 24 Hours"});
}

export const candidateLoginController = async (request, response) => {
    try {
        const candidateObj = await candidateSchema.findOne({ _id: request.body.email });
        if (!candidateObj) throw new Error("Candidate not exist");

        const isMatch = await bcrypt.compare(request.body.password, candidateObj.password);

        if (isMatch && candidateObj.status && candidateObj.adminVerify === "Verified") {
            const token = jwt.sign({ email: request.body.email }, candidate_secret_key, { expiresIn: '1d' });

            response.cookie('candidate_jwt_token', token, { maxAge: 24 * 60 * 60 * 1000, httpOnly: true });
            response.render("candidateHome", { email: request.body.email });
        } else {
            response.render("candidateLogin", { message: "Incorrect password or admin approval pending" });
        }

    } catch (error) {
        console.log("Error in candidateLogin:", error);
        response.render("candidateLogin", { message: "Candidate doesn't exist or login error" });
    }
};

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

            const previewURL = await mailer(mailContent, email); // ✅ returns preview URL
            res.render('candidateForgotPassword', {
            message: 'Reset link has been sent to your email (Preview URL below)',
            previewUrl: previewURL  // ✅ Changed to match EJS
});
    }catch (error) {
        console.log("Error in sending reset link:", error);
        res.render('candidateForgotPassword', { message: 'An error occurred. Please try again.' });
    }
};


export const showResetPasswordFormController = async (req, res) => {
  const { token } = req.params;
  try {
    jwt.verify(token, candidate_secret_key); // only to check token validity
    res.render("candidateResetPassword", { message: "", token }); // send token to view
  } catch (error) {
    res.render("candidateResetPassword", { message: "Token expired or invalid", token: null });
  }
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
