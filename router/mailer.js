import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

var mailer = function(mailContent,email,callback){
    const transporter = nodemailer.createTransport({
        service:'gmail',
        auth:{
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        }
    });    
    const mailOption = {
        from : process.env.EMAIL_USER,
        to : email,
        subject :"Verification Mail by RecruitEase",
        html: mailContent
    }
    transporter.sendMail(mailOption,(error,info)=>{
        if(error)
            console.log("Error while sending mail inside sendMail");
        else{
            console.log("Mail sent from sendMail");
            callback(info);
        }            
    });
};
export default {mailer:mailer};
