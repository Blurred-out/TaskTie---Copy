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
import fs from "fs";
import { instrument } from "@socket.io/admin-ui"

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: ["https://admin.socket.io"],
        credentials: true
    }
})
instrument(io, {
    auth: false,
    mode: "development"
})
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
        const fileName = `img_${new Date().getTime()}${ext}`;
        cb(null, fileName);
    }
});
const upload = multer({ storage: storage });


let room;
// --  socket io setup    --
io.on("connection", (socket) => {
    /*      chat socket      */
    // console.log("connected to server, socket_id:",socket.id)
    socket.on("join-room", roomId => {
        socket.roomId = roomId;
        socket.join(roomId);
        room = io.sockets.adapter.rooms.get(socket.roomId)    //use this to check the number of sockets ina  room
        console.log(room.size)

        io.to(socket.roomId).emit("room-size", room.size)

        socket.on("update-read-receipt", async(senderId, receiverId) => {
            // receiverId_senderId
            console.log(senderId, receiverId);
            await db.query(`UPDATE chat.messages SET read_receipt = 'true' WHERE conversation_id = $1`, [receiverId + '_' + senderId])
            io.to(socket.roomId).emit("updated-read-receipt", receiverId, senderId)
            io.to(receiverId).emit("updated-read-receipt", receiverId, senderId)
            console.log('read receipt event emitted!, room id: ', socket.roomId)
        })
    })

    socket.on("leave-room", roomName => {
        console.log("leaving room: ",roomName)
        socket.leave(roomName)
        room = io.sockets.adapter.rooms.get(roomName);
        if (room) {
            console.log(room.size);
            io.to(roomName).emit("room-size", room.size);
        }
    })

    //for realtime updates on active users in a chatroom
    socket.on("disconnect", () => {
        if(socket.roomId){
            console.log("disconnecting from chat room: ",socket.roomId);
            io.to(socket.roomId).emit("room-size", 1)
        } else if (socket.mapRoomId) {
            console.log("disconnecting from map room: ",socket.mapRoomId);
        }
        
    })

    socket.on("text-message", async(message) => {
        console.log(message)
        await db.query(
            `INSERT INTO chat.messages(conversation_id, sender_id, receiver_id, text, timestamp, read_receipt)
            VALUES($1, $2, $3, $4, $5, $6)`,
            [message.convoId, message.senderId, message.receiverId, message.text, message.timestamp, message.readReceipt]
        )
        const time = new Date(message.timestamp);
        const formattedTime = time.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true })
        console.log(formattedTime)
        io.to(socket.roomId).emit("message-received", formattedTime, message.text, message.senderId, message.receiverId, message.readReceipt)
        // if(room.size === 1){
            io.to(message.receiverId).emit("message-received", formattedTime, message.text, message.senderId, message.receiverId, message.readReceipt, message.receiverRole)
        // }
        console.log("event emitted")
    })

    socket.on("image-message", async(data) => {
        
        const { image, convoId, senderId, receiverId, timestamp, readReceipt, receiverRole } = data;
        console.log("imageData: ",image, convoId)

        try {
            const buffer = Buffer.from(image, 'base64');
            const fileName = `img_${new Date().getTime()}.png`;
            fs.writeFileSync(`uploads/${fileName}`, buffer);

            // Insert into database
            await db.query(
                `INSERT INTO chat.messages(conversation_id, sender_id, receiver_id, image_name, timestamp, read_receipt)
                VALUES($1, $2, $3, $4, $5, $6)`,
                [convoId, senderId, receiverId, fileName, timestamp, false]
            );

            const time = new Date(timestamp);
            const formattedTime = time.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true })

            // Emit event to inform clients about the new image
            io.to(socket.roomId).emit("image-received", fileName, formattedTime, senderId, receiverId, readReceipt);
            // if(room.size === 1){
            io.to(receiverId).emit("image-received", fileName, formattedTime, senderId, receiverId, readReceipt, receiverRole);
            // }
            console.log(formattedTime)
            console.log("event emitted with socket id: ", socket.id)

        } catch (err) {
            console.error("Error handling image upload:", err);
        }
    })

    /*      map socket       */
    socket.on("join-map-room", mapRoomId => {
        socket.mapRoomId = mapRoomId;
        socket.join(mapRoomId);
        io.to(mapRoomId).emit("map-room-joined")
        console.log("joined room: ", mapRoomId);
    })

    socket.on("update-agent-location", async (id, coords) => {
        console.log("new location: ", id, coords, socket.mapRoomId);
        await db.query("UPDATE map.delivery_agent_details SET latitude = $1, longitude = $2 WHERE user_id = $3", [coords.lat, coords.lng, id])
        io.to(socket.mapRoomId).emit("agent-location-updated", id, coords)
    })
})

// --   socket fxns    --

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
                const id = uniqid();
            db.query("INSERT INTO company_details(id, name, email, code, image_name, password, role) VALUES($1, $2, $3, $4, $5, $6, $7)", [id, name, email, code, fileName, hash, "company"])
            db.query("INSERT INTO chat.users(user_id, name) VALUES($1, $2)", [id, name])
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
            const checkTeamManager = await db.query("SELECT * FROM team_details WHERE manager_email = $1", [email])
            if (checkManager.rows.length > 0) {
                res.status(400).json({message: "Email already registered. Please try logging in."})
            } else if(checkTeamManager.rows.length > 0){
                res.status(400).json({message: "Manager for the team already exists!"})
            } else {
                const id = uniqid();
                db.query(
                    "INSERT INTO manager_details(id, name, email, team_code, company_code, image_name, password, phone_no, role) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    [id, name, email, teamCode, companyCode, fileName, hash, phoneNo, "manager"]
                )
                db.query("INSERT INTO chat.users(user_id, name) VALUES($1, $2)", [id, name])
                db.query("UPDATE team_details SET manager_email = $1 WHERE team_code = $2", [email, teamCode])
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
    const loc = JSON.parse(req.body.coords)
    console.log(loc)
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
                const id = uniqid();
                db.query(
                    "INSERT INTO delivery_agent_details(id, name, email, team_code, company_code, image_name, password, phone_no, role) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    [id, name, email, teamCode, companyCode, fileName, hash, phoneNo, "delivery_agent"]
                )
                db.query("INSERT INTO chat.users(user_id, name) VALUES($1, $2)", [id, name])
                db.query("INSERT INTO map.delivery_agent(name, user_id, latitude, longitude, image_name) VALUES($1, $2, $3, $4, $5)", [name, id, loc.lat, loc.lng, fileName])
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
    const loc = JSON.parse(req.body.coords)
    let fileName;
    if(req.file){fileName = req.file.filename}
    console.log(loc)

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
                const id = uniqid();
                await db.query(
                    "INSERT INTO outlet_details(id, name, email, address, team_code, company_code, image_name, password, phone_no, role) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                    [id, name, email, address, teamCode, companyCode, fileName, hash, phoneNo, "outlet"]
                )
                await db.query("INSERT INTO chat.users(user_id, name) VALUES($1, $2)", [id, name])
                await db.query("INSERT INTO map.outlet(name,  user_id, address, latitude, longitude, image_name) VALUES($1, $2, $3, $4, $5, $6)", [name, id, address, loc.lat, loc.lng, fileName])
                res.sendStatus(200)
            }
        } catch (err) {
            console.log(err)
            res.status(500).json({message: "Internal server error"}); //not the right approach
        }
    })
})

app.post("/registerTeam", upload.none(), async (req, res) => {
    try {
        console.log("team data: ",req.body)
        const { teamName, teamCode, companyEmail, companyCode } = req.body;
        console.log(teamCode, teamName, companyCode, companyEmail)

        await db.query("INSERT INTO team_details(team_code, company_code, company_email, team_name) VALUES($1, $2, $3, $4)", [teamCode, companyCode, companyEmail, teamName])
        res.sendStatus(200)
    } catch (error) {
        console.log(error)
        res.sendStatus(500)
    }
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


// --   login/logout handlers   --
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


//  --  chat handlers   --
app.post("/chatListData", async (req, res) => {
    const {id, role, company_code: code = req.body.code, email, team_code} = req.body //code is company code, id is the the currently logged-in user id.. role is the user type
    console.log("id: ", id, "role: ", role, "code: ", code, team_code);

    //fectching teams
    let teamResult;
    if(role === "manager"){
        teamResult = await db.query("SELECT * FROM team_details WHERE company_code = $1 AND manager_email = $2", [code, email])
    } else {
        teamResult = await db.query("SELECT * FROM team_details WHERE company_code = $1", [code])
    }

    // console.log(teamResult.rows)

    //fetches details from a particular table (manager/agent/outlet_details)
    async function fetchDetails(tableName, teamCode, id) {
        const result = await db.query(`SELECT * FROM ${tableName} WHERE team_code = $1`, [teamCode]);
        const data = [];
    
        for (const rowData of result.rows) {
            // Log each rowData to ensure you're processing the correct data
            // console.log("Processing rowData: ", rowData);
    
            // Fetch the latest message for each user
            const messageData = await db.query(`
                WITH latest_messages AS (
                    (SELECT *
                    FROM chat.messages
                    WHERE conversation_id = $1
                    ORDER BY timestamp DESC
                    LIMIT 1)
                    UNION ALL
                    (SELECT *
                    FROM chat.messages
                    WHERE conversation_id = $2
                    ORDER BY timestamp DESC
                    LIMIT 1)
                )
                SELECT *
                FROM latest_messages
                ORDER BY timestamp DESC
                LIMIT 1;
            `, [id + "_" + rowData.id, rowData.id + "_" + id]);
    
            let message;
            if (messageData.rows.length > 0) {
                const { text, timestamp, read_receipt, sender_id } = messageData.rows[0];
                const time = new Date(timestamp);
                const formattedTime = time.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
                message = { text, timestamp: formattedTime, readReceipt: read_receipt, senderId: sender_id };
            } else {
                message = { text: "", timestamp: null, readReceipt: "false", senderId: "" };
            }
    
            // Determine role based on table name
            let role;
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
                case 'company_details':
                    role = 'Company';
                    break;
                default:
                    role = 'Unknown';
            }
    
            // Collect data for the current row
            data.push({
                name: rowData.name,
                id: rowData.id,
                image_name: rowData.image_name,
                message,
                role
            });
        }
        // console.log("result: ", data)
        return data;
    }
    
    //fetches details from company_details
    async function fetchCompanyDetails(){
        const result = await db.query("SELECT * FROM company_details WHERE code = $1", [code])
        // console.log(result.rows)
        let data = null;
        let message = null;
        if(result.rows.length > 0){
            const rowData = result.rows[0];
            const messageData = await db.query(`
            WITH latest_messages AS (
                (SELECT *
                FROM chat.messages
                WHERE conversation_id = $1
                ORDER BY timestamp DESC
                LIMIT 1)
                UNION ALL
                (SELECT *
                FROM chat.messages
                WHERE conversation_id = $2
                ORDER BY timestamp DESC
                LIMIT 1)
            )
            SELECT *
            FROM latest_messages
            ORDER BY timestamp DESC
            LIMIT 1;
            `, [id + "_" + rowData.id, rowData.id + "_" + id]);
    
            if (messageData.rows.length > 0) {
                const { text, timestamp, read_receipt, sender_id } = messageData.rows[0];
                const time = new Date(timestamp);
                const formattedTime = time.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true })
                message = { text, timestamp: formattedTime, readReceipt: read_receipt, senderId: sender_id };
            } else {
                message = { text: "", timestamp: null, readReceipt: "false", senderId: "" };
            }

            data = {
                name: rowData.name,
                id: rowData.id,
                image_name: rowData.image_name,
                message,
                role: "Company",
            };
        }
        return data;
    }
    
    let data;
    if (role === 'company') {
        data = await Promise.all(teamResult.rows.map(async (team) => {
            //fetches all 3 types of user details
            const managerData = await fetchDetails("manager_details", team.team_code, id);
            const deliveryAgentData = await fetchDetails("delivery_agent_details", team.team_code, id);
            const outletData = await fetchDetails("outlet_details", team.team_code, id);
            console.log(managerData)
        
            let chatData = null;
            if (managerData || deliveryAgentData || outletData) {
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: [...managerData, ...deliveryAgentData, ...outletData].filter(Boolean) // Filter out null values
                };
            } else {
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: null
                };
            }
            return chatData;
        }));
    } else if (role === 'manager') {
        const companyData = await fetchCompanyDetails();

        data = await Promise.all(teamResult.rows.map(async (team) => {
            const deliveryAgentData = await fetchDetails("delivery_agent_details", team.team_code, id);
            const outletData = await fetchDetails("outlet_details", team.team_code, id);
            
            let chatData = null;
            if(deliveryAgentData || outletData || companyData){
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: [...deliveryAgentData, ...outletData].filter(Boolean) //Filter out null values
                };
            } else {
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: null
                };
            }
            
            return chatData;
        }));
        // let companyData = await fetchCompanyDetails();
        data = [...data, companyData]
    } else if (role === "delivery_agent") {
        
        const companyData = await fetchCompanyDetails();
        const managerData = await fetchDetails("manager_details", team_code, id);
        data = await Promise.all(teamResult.rows.map(async (team) => {
            if(team.team_code === team_code){
                const outletData = await fetchDetails("outlet_details", team.team_code, id);
            
                let chatData = null;
                if(outletData){
                    chatData = {
                        teamName: team.team_name,
                        teamCode: team.team_code,
                        teamData: [...outletData].filter(Boolean) //Filter out null values
                    };
                } else {
                    chatData = {
                        teamName: team.team_name,
                        teamCode: team.team_code,
                        teamData: null
                    };
                }
                return chatData;
            }
        }));
        data = [...data, companyData, managerData[0]].filter(Boolean)
    } else if (role === "outlet") {
        const companyData = await fetchCompanyDetails();
        const managerData = await fetchDetails("manager_details", team_code, id);
        data = await Promise.all(teamResult.rows.map(async (team) => {
            if(team.team_code === team_code){
                const deliveryAgentData = await fetchDetails("delivery_agent_details", team.team_code, id);
            
                let chatData = null;
                if(deliveryAgentData){
                    chatData = {
                        teamName: team.team_name,
                        teamCode: team.team_code,
                        teamData: [...deliveryAgentData].filter(Boolean) //Filter out null values
                    };
                } else {
                    chatData = {
                        teamName: team.team_name,
                        teamCode: team.team_code,
                        teamData: null
                    };
                }
                return chatData;
            }
        }));
        data = [...data, companyData, managerData[0]].filter(Boolean)
    }

    console.log("\n\nfinal data: ",data)
    res.status(200).json(data)
})

app.post("/getMessages", upload.none(), async (req, res) => {
    const receivedData = req.body;
    // console.log(receivedData)

    const senderResult = await db.query("SELECT (id, timestamp, text, image_name, read_receipt) FROM chat.messages WHERE conversation_id = $1", [receivedData.sender + "_" + receivedData.receiver]);
    const receiverResult = await db.query("SELECT (id, timestamp, text, image_name, read_receipt) FROM chat.messages WHERE conversation_id = $1", [receivedData.receiver + "_" + receivedData.sender]);

    const senderWithOwn = senderResult.rows.map((message) => {
        return {...message, own: true}
    })
    const receiverWithOwn = receiverResult.rows.map((message) => {
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


// --   map handlers    --
app.post("/mapListData", async(req, res) => {
    const {id, role, code: companyCode, email, team_code: teamCode} = req.body;
    console.log(id, role, companyCode ,email, teamCode);

    let teamResult;
    if (role === "company") {
        teamResult = await db.query(`SELECT * FROM team_details WHERE company_code = $1`, [companyCode])
        // console.log(teamResult.rows)
    } else if (role === "manager") {
        teamResult = await db.query(`SELECT * FROM team_details WHERE manager_email = $1`, [email])
    } else if (role === "outlet" || role === "delivery_agent") {
        teamResult = await db.query(`SELECT * FROM team_details WHERE team_code = $1`, [teamCode])
    }

    async function fetchTeamData(tableName, teamCode, id = null){
        let result;
        if (id === null) {
            result = await db.query(`SELECT * FROM ${tableName} WHERE team_code = $1`, [teamCode])
        } else {
            result = await db.query(`SELECT * FROM ${tableName} WHERE id = $1`, [id])
        }
        
        let data = [];

        let role;
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
            case 'company_details':
                role = 'Company';
                break;
            default:
                role = 'Unknown';
        }

        for(const rowData of result.rows) {
            let locData;
            if (role === "Agent" || role === "Outlet") {
                locData = await fetchLocationFromDB(tableName, rowData.id)
            }
            // console.log(rowData)

            data.push({
                id: rowData.id,
                name: rowData.name,
                role,
                image_name: rowData.image_name,
                address: rowData.address,
                phone_no: rowData.phone_no,
                coords:{
                    lat: locData[0]?.latitude,
                    lng: locData[0]?.longitude
                },
                company_code: rowData.company_code,
            });
        }
        // console.log("L773:", data)
        return data;
    }

    async function fetchLocationFromDB(table_name, user_id){
        const result = await db.query(`SELECT * FROM map.${table_name} WHERE user_id = $1`, [user_id])
        return result.rows;
    }

    let data;
    if (role === "company" || role === "manager") {
        data = await Promise.all(teamResult.rows.map(async (team) => {
            const outletData = await fetchTeamData("outlet_details", team.team_code)
            const deliveryAgentData = await fetchTeamData("delivery_agent_details", team.team_code)

            let chatData = null;
            if (outletData || deliveryAgentData) {
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: [...outletData, ...deliveryAgentData]
                };
            } else {
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: null
                };
            }
            return chatData;
        }))
    } else if (role === "outlet") {
        data = await Promise.all(teamResult.rows.map(async (team) => {
            const outletData = await fetchTeamData("outlet_details", team.team_code, id)
            const deliveryAgentData = await fetchTeamData("delivery_agent_details", team.team_code)

            let chatData = null;
            if (deliveryAgentData) {
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: [...outletData, ...deliveryAgentData]
                };
            } else {
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: null
                };
            }
            return chatData;
        }))
    } else if (role === "delivery_agent") {
        data = await Promise.all(teamResult.rows.map(async (team) => {
            const outletData = await fetchTeamData("outlet_details", team.team_code)
            const deliveryAgentData = await fetchTeamData("delivery_agent_details", team.team_code,id)

            let chatData = null;
            if (deliveryAgentData) {
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: [...outletData, ...deliveryAgentData]
                };
            } else {
                chatData = {
                    teamName: team.team_name,
                    teamCode: team.team_code,
                    teamData: null
                };
            }
            return chatData;
        }))
    }

    console.log("final: ", data)
    res.status(200).json(data)
})


// --   product handlers    --
app.post("/productsListData", async(req, res) => {
    let companyCode;
    if (req.body.role === "company"){
        companyCode = req.body.code
    } else {
        companyCode = req.body.company_code
    }
    const result = await db.query("SELECT * FROM product.products WHERE company_code = $1", [companyCode])
    console.log(result.rows)

    res.status(200).json(result.rows)
})

app.post("/registerProduct", upload.single("image"), async (req, res) => {
    let fileName;
    if(req.file){
        fileName = req.file.filename;
    }
    // name description 72 123456789045 7YP53P undefined
    const {name, description, price, UPC, company_code: companyCode, created_at: createdAt} = req.body;
    console.log(name, description, price, UPC, companyCode, fileName, createdAt)

    await db.query("INSERT INTO product.products (product_id, name, description, price, image_name, upc, company_code, created_at, availability_status) VALUES($1, $2, $3, $4, $5, $6, $7, $8, 'In stock')", [uniqid(), name, description, price, fileName, UPC, companyCode, createdAt])
    res.sendStatus(200)
})

app.post("/getProductData/:productId", async(req, res) => {
    //logic to fetch and send product data
    console.log(req.body, req.params["productId"].slice(1))
    const result = await db.query("SELECT * FROM product.products WHERE company_code = $1 AND product_id = $2", [req.body.companyCode, req.params["productId"].slice(1)])
    console.log(result.rows)

    res.status(200).json(result.rows[0])
})

app.post("/editProduct", upload.single("image"), async (req, res) => {
    let { productId, name, description, price, discounted_price: discountPrice, availabilityStatus, UPC, companyCode, editedAt, existingImage } = req.body
    let fileName = existingImage
    if(req.file){
    fileName = req.file.filename;
    }

    if(discountPrice === ""){
        discountPrice = null;
    }

    console.log({ productId, name, description, price, discountPrice, availabilityStatus, UPC, companyCode, editedAt, fileName })

    await db.query(
        "UPDATE product.products SET name = $1, description = $2, price = $3, discounted_price = $4, image_name = $5, availability_status = $6, upc = $7, edited_at = $8 WHERE company_code = $9 AND product_id = $10",
        [name, description, price, discountPrice, fileName, availabilityStatus, UPC, editedAt, companyCode, productId]
    )

    res.sendStatus(200)
})

app.post("/deleteProduct/:productId", async (req, res) => {
    const productId = req.params["productId"].slice(1)
    const { companyCode } = req.body;
    console.log( req.body, companyCode, productId )
    try {
    await db.query("DELETE FROM product.products WHERE product_id = $1 AND company_code = $2", [productId, companyCode])
    res.sendStatus(200)
    } catch (error) {
        console.log("Error deleting product: ",error);
        res.sendStatus(500)
    }
})

app.post("/product/data/:productId", async (req, res) => {
    const productId = req.params["productId"].slice(1);
    let companyCode;
    if (req.body.role === "company"){
        companyCode = req.body.code
    } else {
        companyCode = req.body.company_code
    }
    try {
        console.log(companyCode, productId)
        const result = await db.query("SELECT * FROM product.products WHERE product_id = $1 AND company_code = $2", [productId, companyCode])
        res.status(200).json(result.rows[0])
    } catch (error) {
        console.log("Error fetching error: ", error)
        res.sendStatus(500)
    }
})

// [
//     {
//       product_id: 'txp',
//       quantity: 2,
//       product_name: 'u see...i',
//       price: 43,
//       total_price: 86
//     },
//     {
//       product_id: 'txjga9bclx6ykvu5',
//       quantity: 6,
//       product_name: 'was it worth it?',
//       price: 335,
//       total_price: 2010
//     }
//   ] {
//     id: 'txjga5r0lwiktyud',
//     name: 'user_O',
//     email: 'outlet@gmail.com',
//     team_code: 'poke',
//     company_code: '7YP53P',
//     image_name: null,
//     password: '$2b$10$.kTqyrK0VCjgQEaVcGumYuqk800ZcCIieGX5HRauNCeLbd57PT4vW',
//     phone_no: '0987654321',
//     address: 'outlet..near outlet',
//     role: 'outlet'
//   }

app.post("/updateCart", async (req, res) => {
    const { cart, user } = req.body;
    console.log(cart, user);

    const checkCart = await db.query("SELECT * FROM order_details.cart WHERE user_id = $1", [user.id]);
    if (checkCart.rows.length > 0) {
        for (const item of cart) {
            const checkItem = await db.query("SELECT * FROM order_details.cart_items WHERE cart_id = $1 AND product_id = $2", [checkCart.rows[0].cart_id, item.product_id]);
            console.log("checkItem result: ", checkItem.rows);

            if (checkItem.rows.length > 0) {
                // If the item already exists, increment the quantity
                const currentQuantity = checkItem.rows[0].quantity;
                const newQuantity = currentQuantity + item.quantity;
                if (newQuantity > 0) {
                    const totalAmount = newQuantity * item.price;
                    await db.query("UPDATE order_details.cart_items SET quantity = $1, price_per_unit = $2, total_amount = $3 WHERE cart_id = $4 AND product_id = $5", [newQuantity, item.price, totalAmount, checkCart.rows[0].cart_id, item.product_id]);
                } else {
                    // Do not delete the item if the new quantity is 0
                    console.log(`Skipping update for product_id ${item.product_id} as new quantity is 0`);
                }
            } else {
                if (item.quantity > 0) {
                    // Insert the new item
                    await db.query("INSERT INTO order_details.cart_items(cart_id, product_id, product_name, quantity, outlet_id, outlet_name, price_per_unit, total_amount) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)", [checkCart.rows[0].cart_id, item.product_id, item.product_name, item.quantity, user.id, user.name, item.price, item.total_price]);
                }
            }
        }
    } else {
        await db.query("INSERT INTO order_details.cart (user_id, amount) VALUES ($1, $2)", [user.id, 0]);
    }

    res.status(200).send("Cart updated successfully");
});

app.post("/updateCartDirect", async (req, res) => {
    const { cart, user } = req.body;
    console.log(cart, user);

        for (const item of cart) {
            await db.query("UPDATE order_details.cart_items SET quantity = $1, total_amount = $2 WHERE cart_id = $3 AND product_id = $4", [item.quantity, item.total_amount, item.cart_id, item.product_id])
        }

    res.status(200).send("Cart updated successfully");
});


app.post("/cartDetails", async (req, res) => {
    const user = req.body;
    try {
        const result = await db.query(`
            SELECT 
                ci.*, 
                p.image_name,
                CASE 
                    WHEN p.discounted_price IS NOT NULL THEN p.discounted_price 
                    ELSE p.price 
                END AS price_per_unit
            FROM order_details.cart_items ci
            JOIN product.products p ON ci.product_id = p.product_id
            WHERE ci.outlet_id = $1
        `, [user.id]);
        res.status(200).json(result.rows);
    } catch (error) {
        console.log(error);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/order", async (req, res) => {
    const { cart, user, timestamp } = req.body;
    console.log(cart, user);
    
    const data = cart.filter((item) => {
        return item.quantity > 0 && item.quantity 
    })
    console.log(data)

    let totalPrice = data.reduce((acc, item) => acc + item.total_amount, 0)
    
    const orderResult = await db.query("INSERT INTO order_details.orders(order_timestamp, status, amount) VALUES($1, $2, $3) RETURNING *;", [timestamp, "waiting to be accepted", totalPrice])
    let orderId = orderResult.rows[0].order_id;
    console.log("orderid: ", orderId)

    for (const item of data) {
        await db.query("INSERT INTO order_details.order_items(product_id, product_name, quantity, outlet_id, outlet_name, price_per_unit, total_amount, order_id) VALUES($1, $2, $3, $4, $5, $6, $7, $8)",
        [item.product_id, item.product_name, item.quantity, user.id, user.name, item.price_per_unit, item.total_amount, orderId])
    }

    for (const item of cart){
        await db.query("DELETE FROM order_details.cart_items WHERE cart_id = $1 AND outlet_id = $2", [item.cart_id, user.id])
    }

    res.sendStatus(200);
})


// --   others  --
app.get("/currentUser", (req, res) => {
    res.status(200).json(req.user);
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
                    redirectURL = '/delivery_agent/home';
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
        }
    )
);

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