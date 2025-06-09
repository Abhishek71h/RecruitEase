import uuid4 from 'uuid4';
import appliedVacancySchema from '../model/appliedVacancySchema.js';
import vacancySchema from '../model/vacancySchema.js';
export const candidateAppliedVacancyController = async(request,response) =>{
    try{
        const appliedVacancyId = uuid4();
        const candidateData = JSON.parse(request.query.data);
        candidateData.appliedVacancyId = appliedVacancyId;
        // console.log("candidateData",candidateData);
        const vacancyList = await vacancySchema.find();

        const status = await appliedVacancySchema.create(candidateData);
        const candidateVacancyRecord = await appliedVacancySchema.find({candidateEmail:request.payload.email});
        response.render("candidateVacancyList",{email:request.payload.email,vacancyList:vacancyList,message:"Successfully Applied",status:candidateVacancyRecord});
    } catch(error){
        console.log("Error: ",error);
    }
};
