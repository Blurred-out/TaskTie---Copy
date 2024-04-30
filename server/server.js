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
import { Server } from "socket.io";
import http from "http";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server)
const port = 5000;
const saltingRounds = 10;


// --   pg setup    --
const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "Task_tie",
    password: "Blurry_XD",
    port: 5432,
});
db.connect();


// --   xpress middleware   --
app.use(express.json());
app.use(express.urlencoded({extended: true}));
// app.use(express.static("public"))
app.use("/uploads", express.static("uploads"));


// --   session setup   --
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


// --   multer setup    --
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


// --   io setup    --
io.on("connection", (socket) => {
    console.log("connected to server, socket_id:",socket.id)
    socket.on("user-message", async(message) => {
        console.log(message)
        await db.query("INSERT INTO chat.messages")
    })
    socket.on("user-image", (image_name) => {
        console.log(image_name)
    })
})


// --   register handlers   --
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


// --   fetching team/company name  --
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


// --   login logout handlers   --
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


// --   others  --
app.post("/chatListData", async (req, res) => {
    const {code, id} = req.body
    console.log("id", id);
    const teamResult = await db.query("SELECT * FROM team_details WHERE company_code = $1", [code])

    async function fetchDetails(tableName, teamCode, id) {
        const result = await db.query(`SELECT * FROM ${tableName} WHERE team_code = $1`, [teamCode]);
        let data = null;
        let message = null;
        let role = null;
        if (result.rows.length > 0) {
            const rowData = result.rows[0];
            // returns the latest message of a user
            const messageData = await db.query(`
                SELECT m.*
                FROM chat.messages m
                INNER JOIN (
                    SELECT conversation_id, MAX(timestamp) AS max_timestamp
                    FROM chat.messages
                    GROUP BY conversation_id
                ) latest ON m.conversation_id = latest.conversation_id AND m.timestamp = latest.max_timestamp
                WHERE m.conversation_id = $1;
            `, [id + "_" + rowData.id]);
    
            if (messageData.rows.length > 0) {
                const { text, timestamp } = messageData.rows[0];
                message = { text, timestamp };
            } else {
                message = { text: "", timestamp: null };
            }
    
            // Determine role based on table name
            switch (tableName) {
                case 'manager_details':
                    role = 'Manager';
                    break;
                case 'delivery_agent_details':
                    role = 'Agent';
                    break;
                case 'outlet_details':
                    role = 'Outlet';
                    break;
                default:
                    role = 'Unknown';
            }
    
            data = {
                name: rowData.name,
                id: rowData.id,
                img: rowData.logo,
                message,
                role
            };
        }
        return data;
    }
    
    let data = await Promise.all(teamResult.rows.map(async (team) => {
        //fetches all 3 types of user details
        const managerData = await fetchDetails("manager_details", team.team_code, id);
        const deliveryAgentData = await fetchDetails("delivery_agent_details", team.team_code, id);
        const outletData = await fetchDetails("outlet_details", team.team_code, id);
    
        let chatData = null;
        if (managerData || deliveryAgentData || outletData) {
            chatData = {
                teamName: team.team_name,
                teamCode: team.team_code,
                teamData: [managerData, deliveryAgentData, outletData].filter(Boolean) // Filter out null values
            };
        }
        return chatData;
    })); 

    res.status(200).json(data)
})

app.get("/currentUser", (req, res) => {
    res.status(200).json(req.user);
})

app.post("/getMessages", upload.none(), async (req, res) => {
    const receivedData = req.body;

    const senderResult = await db.query("SELECT (id, timestamp, text, image_name) FROM chat.messages WHERE conversation_id = $1", [receivedData.sender + "_" + receivedData.receiver]);
    const receiverResult = await db.query("SELECT (id, timestamp, text, image_name) FROM chat.messages WHERE conversation_id = $1", [receivedData.receiver + "_" + receivedData.sender]);

    const senderWithOwn = receiverResult.rows.map((message) => {
        return {...message, own: true}
    })
    const receiverWithOwn = senderResult.rows.map((message) => {
        return {...message, own: false}
    })
    
    const mergedData = [...receiverWithOwn, ...senderWithOwn]
    
    const sortedData = mergedData.sort((a,b) => {
        const timestampRegex = /"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})"/;
        const timestampA = new Date(a.row.match(timestampRegex)[1]); // Extract timestamp using regex
        const timestampB = new Date(b.row.match(timestampRegex)[1]);
        return timestampA - timestampB;
    })

    console.log("Receiver: ", receiverWithOwn, "Sender: ", senderWithOwn)
    console.log("merged: ", mergedData ,"sorted: ", sortedData)
    res.status(200).json(sortedData)
})


// --   passport => auth    --
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


// --   global error handler    --
app.use((err, req, res, next) => {
    console.log("from global error handler: ",err.stack);
    res.status(500).json({message: "Internal Server error"})
})

server.listen(port, () => {
    console.log(`server running on port ${port}`)
});