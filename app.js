import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import adminRouter from './router/adminRouter.js';
import recruiterRouter from './router/recruiterRouter.js';
import candidateRouter from './router/candidateRouter.js';
import vacancyRouter from './router/vacancyRouter.js';
import cookieParser from 'cookie-parser';
import expressFileUpload from 'express-fileupload';
import appliedvacancyRouter from './router/appliedVacancyRouter.js';

const app = express();

//__dirname in ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());
app.use(expressFileUpload());

// Set up EJS views (Absolute Path)
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// Home Route
app.get("/", (request, response) => {
    response.render("home");
});

app.get('/services', (req, res) => res.render('services'));  
app.get('/faq', (req, res) => res.render('faq'));
app.get('/about', (req, res) => res.render('about'));

// Use Routers
app.use("/admin", adminRouter);
app.use("/recruiter", recruiterRouter);
app.use("/candidate", candidateRouter);
app.use("/vacancy", vacancyRouter);
app.use("/appliedVacancy", appliedvacancyRouter);

// Start Server
app.listen(3000, () => {
    console.log("Server is running at http://localhost:3000");
});
