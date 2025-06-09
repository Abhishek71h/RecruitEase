import mongoose from "mongoose";
import url from "../database/connection.js";
mongoose.connect(url);
const RecruiterSchema = mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    recruiter: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    contact: {
        type: String,
        required: true
    },
    address: {
        type: String,
        required: true
    },
    status: {
        type: String,
        default: true,
        required: true
    },
    adminVerify: {
        type: String,
        default: "Not Verified",
        required: true
    },
    emailVerify: {
        type: String,
        default: "Not Verified",
        required: true
    },
});
export default mongoose.model('recruiterSchema', RecruiterSchema,'recruiter');