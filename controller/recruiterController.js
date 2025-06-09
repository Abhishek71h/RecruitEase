import bcrypt from 'bcrypt';
import mailer from '../router/mailer.js';
import recruiterSchema from '../model/recruiterSchema.js';
import candidateSchema from '../model/candidateSchema.js';
import jwt from 'jsonwebtoken';
import vacancySchema from '../model/vacancySchema.js';
import dotenv from 'dotenv';
import appliedVacancySchema from '../model/appliedVacancySchema.js';
import fetch from 'node-fetch';



dotenv.config();
var recruiter_secret_key = process.env.RECRUITER_SECRET_KEY;

export const recruiterVerifyEmailController = async (request, response) => {
    const email = request.query.email;
    const updateStatus = { $set: { emailVerify: "Verified" } };
    const updateResult = await recruiterSchema.updateOne({ email: email }, updateStatus);
    //console.log("Update Result : ", updateResult);
    response.render("recruiterLogin", { message: "Email Verified | Admin verification takes 24 Hours" });

    //response.redirect("http://localhost:3000/recruiterLogin?message=Email Verified | Admin verification takes 24 Hours");

    //response.redirect("https://testfrontend-2.onrender.com/recruiterLogin?message=Email Verified | Admin verification takes 24 Hours");

}

// export const recruiterLoginController = async(request,response)=>{
//     try{
//         const {email,password} = request.body;
//         console.log("email : "+email);
//         console.log("password : "+password);

//         const recruiterObj = await recruiterSchema.findOne({email:email});
//         console.log("recruiterObj : ",recruiterObj);

//         const recruiterPassword = recruiterObj?.password;
//         console.log("recruiterObj : ",recruiterPassword);

//     }catch(error){
//         console.log("Error while login : ",error);  
//         response.render("recruiterLogin",{message : "Error while Login"});
//     }
// }

export const recruiterLoginController = async (request, response) => {
    try {
        const recruiterObj = await recruiterSchema.findOne({ email: request.body.email });
        //console.log(recruiterObj);

        const recruiterPassword = recruiterObj.password;
        const recruiterStatus = recruiterObj.status;
        //console.log("recruiterStatus : ", recruiterStatus);
        //console.log("typeof recruiterStatus : ", typeof recruiterStatus);


        const adminVerifyStatus = recruiterObj.adminVerify;
        const emailVerifyStatus = recruiterObj.emailVerify;

        const status = await bcrypt.compare(request.body.password, recruiterPassword);
        if (status && recruiterStatus && adminVerifyStatus == "Verified" && emailVerifyStatus == "Verified") {
            //console.log("Recruiter Password : ",recruiterPassword);
            
            const expireTime = { expiresIn: '1d' };
            const token = jwt.sign({ email: request.body.email }, recruiter_secret_key, expireTime);
            //console.log("Token : ", token);

            if (!token)
                response.render("recruiterLogin", { message: "Error while setting up the token while recruiter login" });
                //response.status(203).send({ message: "Error while setting up the token while recruiter login" });

            response.cookie('recruiter_jwt_token', token, { maxAge: 24 * 60 * 60 * 1000, httpOnly: true });
            response.render("recruiterHome", { email: request.body.email });
            //response.status(200).send({ email: request.body.email ,token:token});
        }
        else
            response.render("recruiterLogin", { message: "Email Id or Password is Wrong" });
            //response.status(203).send({ message: "Email Id or Password is Wrong" });
    } catch (error) {
        console.log("Error in recruiterLogin : ", error);
         response.render("recruiterLogin", { message: "Something Went Wrong" });
        //response.status(500).send({ message: "Something Went Wrong" });
    }
}


export const recruiterRegistrationController = async (request, response) => {
    const { name, recruiter, email, password, contact, address } = request.body;
    try {
        const obj = {
            name: name,
            recruiter: recruiter,
            email: email,
            password: await bcrypt.hash(password, 10),
            contact: contact,
            address: address
        }
        const mailContent = `Hello ${email},<br>This is a verification mail by RecruitEase. You Needs to verify yourself by clicking on the below link.<br><a href='http://localhost:3000/recruiter/verifyEmail?email=${email}'>Click Here To Verify</a>`;


        //const mailContent = `Hello ${email},<br>This is a verification mail by RecruitEase. You Needs to verify yourself by clicking on the below link.<br><a href='http://localhost:3000/recruiter/verifyEmail?email=${email}'>Click Here To Verify</a>`;

        mailer.mailer(mailContent, email, async (info) => {
            if (info) {

                const result = await recruiterSchema.create(obj);
                console.log("Result of recruiter registration : ", result);
                response.render("recruiterLogin", { message: "Email Sent | Please Verify" });
                //response.status(201).send({status:true,message: "Email Sent | Please Verify"});
            } else {
                console.log("Error while sending email");
                response.render("recruiterRegistration", { message: "Error while sending email" });
                //response.status(203).send({status:false,message: "Error while sending email"});
            }
        })


    } catch (error) {
        console.log("Error occured in recruiter registration : ", error);
        response.render("recruiterRegistration.ejs", { message: "Error occured in recruiter registration" });
        //response.status(500).send({status:false,message: "Error occured in recruiter registration"});
    }
}

export const recruiterVacancyPostedController = async (request, response) => {
    try {
        const vacancyList = await vacancySchema.find({ email: request.payload.email });
        //console.log("vacancyList : ", vacancyList);
        if (vacancyList.length == 0) {
            response.render("recruiterVacancyList", { email: request.payload.email, vacancyList: vacancyList, message: "No Record Found" });
        } else {
            response.render("recruiterVacancyList", { email: request.payload.email, vacancyList: vacancyList, message: "" });
        }
    } catch (error) {
        console.log("Error : ", error);
        const vacancyList = await vacancySchema.find({ email: request.payload.email });
        response.render("recruiterVacancyList", { email: request.payload.email, vacancyList: vacancyList, message: "Wait Data is Loading" });
    }
}

export const recruiterLogoutController = async (request, response) => {
    //console.log(response);
    response.clearCookie('recruiter_jwt_token');
    response.render("recruiterLogin", { message: "Recruiter Logout Successfully" });
}


export const appliedCandidateListController = async (request, response) => {
    try {
        const appliedVacancyList = await appliedVacancySchema.find({ recruiterEmail: request.payload.email });

        var result = [];
        for (let i = 0; i < appliedVacancyList.length; i++) {
            var candidateObj = await candidateSchema.findOne({ _id: appliedVacancyList[i].candidateEmail });
            var filename = candidateObj.docs;
            result.push(filename);
        }
        //console.log("result : ",result);

        //console.log("Applied VacancyList : ", appliedVacancyList);
        if (appliedVacancyList.length == 0) {
            response.render("appliedCandidateList", { email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: "No Record Found" });
            //response.status(200).send({status:true,email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: "No Record Found"});
        } else {
            response.render("appliedCandidateList", { email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: "" });
            //response.status(200).send({status:true,email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: ""});
        }
    } catch (error) {
        console.log("Error : ", error);
        const appliedVacancyList = await appliedVacancySchema.find({ recruiterEmail: request.payload.email });

        var result = [];
        for (let i = 0; i < appliedVacancyList.length; i++) {
            var candidateObj = await candidateSchema.findOne({ _id: appliedVacancyList[i].candidateEmail });
            var filename = candidateObj.docs;
            result.push(filename);
        }
        //console.log("result : ",result);

        response.render("appliedCandidateList", { email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: "Wait Data is Loading" });
        //response.status(500).send({status:false,email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: "Wait Data is Loading"});
    }
};

export const recruiterUpdateStatusController = async (request, response) => {
    try {
        const receivedStatus = request.body.recruiterStatus;
        const vacancyId = request.body.vacancyId;
        //console.log("recruiterStatus : ", receivedStatus);
        //console.log("vacancyId : ", vacancyId);

        const updateStatus = {
            $set: {
                recruiterStatus: receivedStatus
            }
        }
        const status = await appliedVacancySchema.updateOne({ vacancyId: vacancyId }, updateStatus);
        //console.log("status : ", status);

        const appliedVacancyList = await appliedVacancySchema.find({ recruiterEmail: request.payload.email });

        var result = [];
        for (let i = 0; i < appliedVacancyList.length; i++) {
            var candidateObj = await candidateSchema.findOne({ _id: appliedVacancyList[i].candidateEmail });
            var filename = candidateObj.docs;
            result.push(filename);
        }
        //console.log("result : ",result);

        response.render("appliedCandidateList", { email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: "Status Updated" });

        //response.status(200).send({status:true,email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: "Status Updated"});

    } catch (error) {
        console.log("Error in recruiterUpdateStatusController : ", error);
        const appliedVacancyList = await appliedVacancySchema.find({ recruiterEmail: request.payload.email });

        var result = [];
        for (let i = 0; i < appliedVacancyList.length; i++) {
            var candidateObj = await candidateSchema.findOne({ _id: appliedVacancyList[i].candidateEmail });
            var filename = candidateObj.docs;
            result.push(filename);
        }
        //console.log("result : ",result);

        response.render("appliedCandidateList", { email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: "Error while Updating Status" });

       // response.status(500).send({status:true,email: request.payload.email, appliedVacancyList: appliedVacancyList, result: result, message: "Error while Updating Status"});
    }
}



export const sendResetLinkController = async (req, res) => {
    const email = req.body.email;

    try {
        const recruiter = await recruiterSchema.findOne({ email });

        if (!recruiter) {
            return res.render("recruiterForgotPassword", { message: "Email not found" });
        }

        const token = jwt.sign({ email: recruiter._id }, process.env.RECRUITER_SECRET_KEY, { expiresIn: '1h' });

        const resetLink = `http://localhost:3000/recruiter/resetPassword/${token}`;

        const mailContent = `
            <h2>Reset Your Password</h2>
            <p>Click the following link to reset your password:</p>
            <a href="${resetLink}">Reset Password</a>
        `;

        mailer.mailer(mailContent, email, (info) => {
            console.log("Reset email sent:", info.response);
        });

        res.render("recruiterForgotPassword", { message: "Reset link sent to your email" });

    } catch (error) {
        console.log("Error in recruiter forgot password:", error);
        res.render("recruiterForgotPassword", { message: "Something went wrong" });
    }
};



export const resetPasswordController = async (req, res) => {
    const { oldPassword, newPassword, confirmPassword } = req.body;
    const { token } = req.params;

    try {
        const decoded = jwt.verify(token, recruiter_secret_key);
        const recruiterId = decoded.email;


        const recruiter = await recruiterSchema.findById(recruiterId);
        
        if (!recruiter) {
            return res.render('recruiterResetPassword', {
                message: 'Recruiter not found',
                token: token 
            });
        }

        const isMatch = await bcrypt.compare(oldPassword, recruiter.password);
        
        if (!isMatch) {
            return res.render('recruiterResetPassword', {
                message: 'Old password is incorrect',
                token: token 
            });
        }

        if (newPassword !== confirmPassword) {
            return res.render('recruiterResetPassword', {
                message: 'New password and confirm password do not match',
                token: token 
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        recruiter.password = hashedPassword;
        await recruiter.save();

        return res.redirect('/recruiter/recruiterLogin?message=Password updated successfully. Please log in.');
    } catch (error) {
        console.log("Error while resetting password:", error);
        return res.render('recruiterResetPassword', {
            message: 'Something went wrong. Please try again.',
            token: token 
        });
    }
};


export const handleRecruiterChat = async (req, res) => {
    const userMessage = req.body.message;
  
    try {
        const ollamaRes = await fetch("http://127.0.0.1:11434/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "llama2",
          prompt: userMessage,
          stream: false,
        }),
      });
  
      const data = await ollamaRes.json();
      const aiReply = data.response.trim();
      //console.log(data);
      res.json({ reply: aiReply });
    } catch (err) {
      console.error("Ollama Chat Error (Recruiter):", err);
      res.status(500).json({ error: "Error communicating with AI" });
    }
  };
  
