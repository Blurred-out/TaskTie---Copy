import express from "express";
import multer from "multer";
import path from "path";
import {fileURLToPath} from "url";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
import uniqid from "uniqid";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 5000;
const saltingRounds = 10;

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "Task_tie",
    password: "Blurry_XD",
    port: 5432,
});
db.connect();

app.use(express.json());
app.use(express.urlencoded({extended: true}));
// app.use(express.static("public"))
app.use("/uploads", express.static("uploads"));

app.use(session({
    secret: "IDONOTKNOW",
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
    }
}));
app.use(passport.initialize());
app.use(passport.session());

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, "uploads"));
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname)
        const fileName = `logo_${new Date().getTime()}${ext}`;
        cb(null, fileName);
    }
});

const upload = multer({ storage: storage });

app.post("/register/company/submit", upload.single('companyProfile'), (req, res) => {
    const {companyName: name, companyEmail: email, companyCode: code, password} = req.body;
    let fileName;
    if(req.file){ fileName = req.file.filename }
    
    bcrypt.hash(password, saltingRounds, async (err, hash) => {
        try{
            const checkCompany = await db.query(
            `SELECT email FROM(
                SELECT email FROM company_details
                UNION
                SELECT email FROM manager_details
                UNION 
                SELECT email FROM outlet_details
                UNION
                SELECT email FROM delivery_agent_details
            ) AS all_emails
            WHERE email = $1`,[email]);
            if(checkCompany.rows.length > 0){
                res.status(400).json({message: "Email already registered. PLease try logging in."})
            }else{
            db.query("INSERT INTO company_details(id, name, email, code, image_name, password) VALUES($1, $2, $3, $4, $5, $6)", [uniqid(), name, email, code, fileName, hash])
            res.sendStatus(200)
            }
        }catch(err){
            console.log(err);
            res.status(500).json({message: "Internal server error"}); //not completely right
        }
    })
})

app.post("/register/manager/submit", upload.single('managerProfile'), (req, res) => {
    let {managerName: name, managerContactNo: phoneNo, managerEmail: email, companyCode, teamCode, password} = req.body
    let fileName;
    if(req.file){fileName = req.file.filename}

    bcrypt.hash(password, saltingRounds, async(err, hash) => {
        try {
            const checkManager = await db.query(
                `SELECT email FROM(
                    SELECT email FROM company_details
                    UNION
                    SELECT email FROM manager_details
                    UNION 
                    SELECT email FROM outlet_details
                    UNION
                    SELECT email FROM delivery_agent_details
                ) AS all_emails
                WHERE email = $1`,[email]);
            if(checkManager.rows.length > 0){
                res.status(400).json({message: "Email already registered. Please try logging in."})
            }else{
                db.query(
                    "INSERT INTO manager_details(id, name, email, team_code, company_code, logo, password, phone_no) VALUES($1, $2, $3, $4, $5, $6, $7, $8)",
                    [uniqid(), name, email, teamCode, companyCode, fileName, hash, phoneNo]
                )
                res.sendStatus(200)
            }
        } catch (err) {
            console.log(err)
            res.status(500).json({message: "Internal server error"}); //not the right approach
        }
    })
})

app.post("/register/deliveryAgent/submit", upload.single('deliveryAgentProfile'), (req, res) => {
    let {deliveryAgentName: name, deliveryAgentContactNo: phoneNo, deliveryAgentEmail: email, companyCode, teamCode, password} = req.body
    let fileName;
    if(req.file){fileName = req.file.filename}

    bcrypt.hash(password, saltingRounds, async(err, hash) => {
        try {
            const checkDeliveryAgent = await db.query(
                `SELECT email FROM(
                    SELECT email FROM company_details
                    UNION
                    SELECT email FROM manager_details
                    UNION 
                    SELECT email FROM outlet_details
                    UNION
                    SELECT email FROM delivery_agent_details
                ) AS all_emails
                WHERE email = $1`,[email]);
            if(checkDeliveryAgent.rows.length > 0){
                res.status(400).json({message: "Email already registered. Please try logging in."})
            }else{
                db.query(
                    "INSERT INTO delivery_agent_details(id, name, email, team_code, company_code, logo, password, phone_no) VALUES($1, $2, $3, $4, $5, $6, $7, $8)",
                    [uniqid(), name, email, teamCode, companyCode, fileName, hash, phoneNo]
                )
                res.sendStatus(200)
            }
        } catch (err) {
            console.log(err)
            res.status(500).json({message: "Internal server error"}); //not the right approach
        }
    })
})

app.post("/register/outlet/submit", upload.single('outletProfile'), (req, res) => {
    let {outletName: name, outletContactNo: phoneNo, outletEmail: email, outletAddress: address, companyCode, teamCode, password} = req.body
    let fileName;
    if(req.file){fileName = req.file.filename}

    bcrypt.hash(password, saltingRounds, async(err, hash) => {
        try {
            const checkOutlet = await db.query(
                `SELECT email FROM(
                    SELECT email FROM company_details
                    UNION
                    SELECT email FROM manager_details
                    UNION 
                    SELECT email FROM outlet_details
                    UNION
                    SELECT email FROM delivery_agent_details
                ) AS all_emails
                WHERE email = $1`,[email]);
            if(checkOutlet.rows.length > 0){
                res.status(400).json({message: "Email already registered. Please try logging in."})
            }else{
                db.query(
                    "INSERT INTO outlet_details(id, name, email, address, team_code, company_code, logo, password, phone_no) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    [uniqid(), name, email, address, teamCode, companyCode, fileName, hash, phoneNo]
                )
                res.sendStatus(200)
            }
        } catch (err) {
            console.log(err)
            res.status(500).json({message: "Internal server error"}); //not the right approach
        }
    })
})

app.get("/getCompanyName", async(req, res) => {
    const companyCode = req.query.companyCode;
    // console.log("triggered");
    try{
        const result = await db.query("SELECT * FROM company_details WHERE code = $1", [companyCode])
        if(result.rows.length > 0){
            let name = result.rows[0].name;
            res.status(200).json({companyName: name})
        } else {
            res.status(404).json({notFound: true})
        }
        
    } catch (error) {
        console.log(error)
        res.status(500)
    }
})

app.get("/getTeamName", async(req, res) => {
    const teamCode = req.query.teamCode;
    // console.log("triggered");
    try{
        const result = await db.query("SELECT * FROM team_details WHERE team_code = $1", [teamCode])
        if(result.rows.length > 0){
            let name = result.rows[0].team_name;
            res.status(200).json({teamName: name})
        } else {
            res.status(404).json({notFound: true})
        }
    } catch (error) {
        console.log(error)
        res.status(500)
    }
})

app.post("/login", upload.none(), passport.authenticate("local"), (req, res) => {
    try{
        const { user, authInfo } = req;

        if(!user){
            return res.sendStatus(401)
        }

        const { message, redirectTo } = authInfo || {}

        res.status(200).json({ message, redirectTo, user });
    } catch (err) {
        console.log(err);
        res.status(500).json({message: "internal server error"})
    }
});

app.post("/logout", (req, res) => {
    try {
        req.logout((err) => {
            if(err){
                console.error("Error during logout: ", err)
                return res.status(500).json({message: "Error during logout"})
            }
            req.session.destroy();
            res.clearCookie('connect.sid', {path: "/"});
            res.status(200).send("Logged out successfully"); 
        });
    } catch(err) {
        console.error("Unexpected error while logging out:", err);
        res.status(500).send("Internal server error"); // Send a result in case of error
    }
})

app.post("/chatListData", async (req, res) => {
    const {code, id} = req.body
    console.log("id", id);
    const teamResult = await db.query("SELECT * FROM team_details WHERE company_code = $1", [code])

    let data = await Promise.all(teamResult.rows.map(async (team) => {
        let managerResult = await db.query("SELECT * FROM manager_details WHERE team_code = $1", [team.team_code])
        // let deliveryAgentResult = await db.query("SELECT * FROM delivery_agent_details WHERE team_code = $1", [team.team_code])
        // let outletResult = await db.query("SELECT * FROM outlet_details WHERE team_code = $1", [team.team_code])
        
        let managerData;
        let message;
        if(managerResult.rows.length > 0){
            managerData = managerResult.rows[0];
            const messageData = await db.query(
                `SELECT m.*
                FROM chat.messages m
                INNER JOIN (
                    SELECT conversation_id, MAX(timestamp) AS max_timestamp
                    FROM chat.messages
                    GROUP BY conversation_id
                ) latest ON m.conversation_id = latest.conversation_id AND m.timestamp = latest.max_timestamp
                WHERE m.conversation_id = $1;
                `, [id + "_" + managerData.id])

            if(messageData.rows.length > 0){
                const {text, timestamp} = messageData.rows[0]
                message = {text, timestamp, role: "manager"}
            } else {
                message = {
                    text: "",
                    timestamp: null,
                    role: "manager"
                }
            }
        }

        // if(deliveryAgentResult.rows.length > 0){
        //     // console.log(deliveryAgentResult.rows)
        // }
        // if(outletResult.rows.length > 0){
        //     // console.log(outletResult.rows)
        // }
        let chatData = managerData ? {
            teamName: team.team_name,
            teamCode: team.team_code,
            teamData: [
                {
                    name: managerData.name,
                    id: managerData.id,
                    img: managerData.logo,
                    ...message
                }
            ]
        } : null
        return chatData;
    }))

    // data.map((entry) => {
    //     console.log("entry: ", entry.teamData)
    // })
    res.status(200).json(data)
})

app.get("/currentUser", (req, res) => {
    // console.log("current_user", req.user)
    res.status(200).json(req.user);
})

passport.use("local",
    new Strategy(
        {usernameField: 'email', 
        passReqToCallback: true},
        async function verify(req, email, password, cb){
            const type = req.body.userType
            console.log(email, password, type)

            let tableName;
            let redirectURL;
            
            try{
                if(type === 'company'){
                    tableName = 'company_details';
                    redirectURL = '/company/home';
                } else if (type === 'manager'){
                    tableName = 'manager_details';
                    redirectURL = '/manager/home';
                } else if(type === 'deliveryAgent'){
                    tableName = 'delivery_agent_details';
                    redirectURL = '/deliveryAgent/home';
                } else if(type === 'outlet'){
                    tableName = 'outlet_details';
                    redirectURL = '/outlet/home';
                }

                const result = await db.query(`SELECT * FROM ${tableName} WHERE email = $1`, [email])
                if(result.rows.length > 0){
                    const storedPwd = result.rows[0].password
                    let user = result.rows[0]
                    console.log(user) //to console.log the current user
                    bcrypt.compare(password, storedPwd, (err, done) => {
                        if(err){
                            return cb(err);
                        }else{
                            if(done){
                                console.log("success")
                                return cb(null, user, {message: "Succesfull login", redirectTo: redirectURL});
                            } else {
                                return cb(null ,false);
                            }
                        }
                    })
                } else {
                    return cb(null, false, {message: "Invalid credentials"});
                }
            } catch (err) {
                console.log(err);
            }
    }));

passport.serializeUser((user, cb) => {
    cb(null, user);
});
passport.deserializeUser((user,cb) => {
    cb(null, user);
});

app.use((err, req, res, next) => {
    console.log(err.stack);
    res.status(500).json({message: "Internal Server error"})
})

app.listen(port, () => {
    console.log(`server running on port ${port}`)
});