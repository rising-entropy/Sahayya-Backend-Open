const functions = require("firebase-functions");
const express = require('express');
const cors = require("cors");
const {Storage} = require('@google-cloud/storage');
const short = require('short-uuid');
const { filesUpload } = require('./middleware');
const fs = require('firebase-admin');
const serviceAccount = require('./service-account.json');
const haversine = require('haversine-distance')
const crypto = require("crypto");
const jwt = require('jsonwebtoken');
const shortUUID = require("short-uuid");
const SECRET = "PaulPogba";

fs.initializeApp({
    credential: fs.credential.cert(serviceAccount)
});

const db = fs.firestore();

const app = express();
const storage = new Storage({
    projectId: "sahayya-9c930",
    keyFilename: "./service-account.json"
});

const translator = short(short.constants.flickrBase58, {
    consistentLength: false,
});
  
const bucket = storage.bucket("gs://sahayya-9c930.appspot.com");
app.use(express.json());
const port = 3000;
app.use(cors({origin: true}));

const uploadImageToStorage = (file) => {
    return new Promise((resolve, reject) => {
        if (!file) {
            reject('No file');
        }
        let fileExtension = file.originalname.split(".");
        fileExtension = fileExtension[fileExtension.length -1];
        let newFileName = `${translator.new()}`+"."+fileExtension;
        let fileUpload = bucket.file(newFileName);
        const blobStream = fileUpload.createWriteStream({
        metadata: {
            contentType: file.mimetype
        }
        });
        blobStream.on('error', (error) => {
            console.log(error)
        reject('Something is wrong! Unable to upload at the moment.');
        });

        blobStream.on('finish', () => {
        // The public URL can be used to directly access the file via HTTP.
        const url = `https://storage.googleapis.com/${bucket.name}/${fileUpload.name}`;
        resolve(url);
        });
        blobStream.end(file.buffer);
    });
};

const validateJWT = token => {
    try{
        var decoded = jwt.verify(token, 'DavidBeckham');
        if(decoded.data === 'PepGuardiola')
        {
            return true;
        }
        return false;
    }
    catch{
        return false;
    }
}


app.get('/', (req, res)=>{
    res.json(
        {
            "message": "Sahayya - Let's Grow Together."
        }
    );
});

app.post('/upload-file', filesUpload, function(req, res) {
   let theFile = req.files[0];
   let file = theFile;
   if (file) {
        uploadImageToStorage(file).then((success) => {
            res.status(201).send({
            message: 'File Uploaded Successfully.',
            link: success
        });
        }).catch((error) => {
        res.status(500).send({
            message: "Some error occurred. Please try again later."
        });
        });
    }
    else
    {
        res.status(404).send({
            message: "No file found."
        });
    }
});

app.post('/ngo-signup', async (req, res)=>{
    let body = req.body;
    let userDb = db.collection('User');

    let [username, email, type, isVerified, password, coOrdinates, picture] = [body.username, body.email, 'NGO', false, body.password, body.coOrdinates, body.picture]
    let [name, regNo, city, state, address, sectors, description] = [body.name, "", body.city, body.state, body.address, body.sectors, body.description]
    
    // check if username exists
    let userRef = db.collection('User').doc(username);
    const doc = await userRef.get();
    if (doc.exists) {
        return res.status(403).json(
            {
                "message": "Username already exists."
            }
        );
    }
    const sha256Hasher = crypto.createHmac("sha256", SECRET);
    password = sha256Hasher.update(password).digest("hex");
    
    const ngoRef = userDb.doc(username); 
    await ngoRef.set({
        username,
        email,
        type,
        isVerified,
        password,
        coOrdinates,
        name,
        regNo,
        city,
        state,
        address,
        sectors,
        description,
        picture
       });

    // 45 day expiry
    const token = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 45),
        data: 'PepGuardiola'
    }, 'DavidBeckham');

    return res.status(201).json({
        "message": 'NGO added successfully.',
        "token": token,
        "username": username
    });
});

app.post('/donor-individual-signup', async (req, res)=>{
    let body = req.body;
    let userDb = db.collection('User');

    let [username, email, type, isVerified, password, coOrdinates, picture] = [body.username, body.email, 'Donor', false, body.password, body.coOrdinates, body.picture]
    let [fName, lName, location, bio, donorType] = [body.fName, body.lName, body.location, body.bio, "Individual"];
    
    // check if username exists
    let userRef = db.collection('User').doc(username);
    const doc = await userRef.get();

    if (doc.exists) {
        return res.status(403).json(
            {
                "message": "Username already exists."
            }
        )
    }
    const sha256Hasher = crypto.createHmac("sha256", SECRET);
    password = sha256Hasher.update(password).digest("hex");
    
    const donorRef = userDb.doc(username);

    await donorRef.set({
        username,
        email,
        type,
        isVerified,
        password,
        coOrdinates,
        picture,
        fName,
        lName,
        location,
        bio,
        donorType
       })

    // 45 day expiry
    const token = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 45),
        data: 'PepGuardiola'
    }, 'DavidBeckham');

    return res.status(201).json({
        "message": 'Individual Donor added successfully.',
        "token": token,
        "username": username
    });
});

app.post('/donor-company-signup', async (req, res)=>{
    let body = req.body;
    let userDb = db.collection('User');

    let [username, email, type, isVerified, password, coOrdinates, picture] = [body.username, body.email, 'Company', false, body.password, body.coOrdinates, body.picture]
    let [name, address, contactNo, sectors, description, donorType] = [body.name, body.address, body.contactNo, body.sectors, body.description, "Company"]
    
    // check if username exists
    let userRef = db.collection('User').doc(username); 
    const doc = await userRef.get();
    if (doc.exists) {
        return res.status(403).json(
            {
                "message": "Username already exists."
            }
        );
    }
    
    const donorRef = userDb.doc(username); 
    await donorRef.set({
        username,
        email,
        type,
        isVerified,
        password,
        coOrdinates,
        picture,
        name,
        address,
        contactNo,
        sectors,
        description,
        donorType
       });

    // 45 day expiry
    const token = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 45),
        data: 'PepGuardiola'
    }, 'DavidBeckham');

    return res.status(201).json({
        "message": 'Company Donor added successfully.',
        "token": token,
        "username": username
    });
});

app.post('/login', async (req, res)=>{
    let body = req.body;
    let userDb = db.collection('User');

    let [username, password] = [body.username, body.password];
    const sha256Hasher = crypto.createHmac("sha256", SECRET);
    password = sha256Hasher.update(password).digest("hex");

    // check if username exists
    let userRef = db.collection('User').doc(username);
    const doc = await userRef.get();
    if (doc.exists) {
        let data = doc.data();
        let vData = data;
        if(data.password === password)
        {
            const token = jwt.sign({
                exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 45),
                data: 'PepGuardiola'
            }, 'DavidBeckham');

            delete vData['password'];

            return res.status(200).json({
                "message": 'Successful Login.',
                "token": token,
                "username": username,
                "data": vData
            });
        }
        return res.status(401).json({
            "message": "Invalid password."
        });
    }
    return res.status(404).json({
        "message": "username does not exist."
    });
});

app.get('/check-token', (req, res)=>{
    let token = req.headers['authorization'];
    if(!validateJWT(token))
    {
        return res.json({
            "message": "Invalid token"
        })
    }
    else
    {
        return res.json({
            "message": "Valid token"
        })
    }
});

app.get('/profile/:username', async (req, res)=>{

    let token = req.headers['authorization'];
    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        })
    }

    let username = req.params.username;
    let userDb = db.collection('User');

    // check if username exists
    let userRef = db.collection('User').doc(username);
    const doc = await userRef.get();
    if (doc.exists) {
        let data = doc.data();
        delete data['password'];
        return res.status(200).json(data);
    }
    return res.status(404).json({
        "message": "username does not exist."
    });
});

app.put('/profile/:username', async (req, res)=>{

    let token = req.headers['authorization'];
    let body = req.body;

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    if("password" in body)
    {
        const sha256Hasher = crypto.createHmac("sha256", SECRET);
        body['password'] = sha256Hasher.update(body['password']).digest("hex");
    }

    if("username" in body)
    {
        delete body["username"];
    }

    let username = req.params.username;
    let userDb = db.collection('User');

    // check if username exists
    let userRef = db.collection('User').doc(username);
    const doc = await userRef.get();
    if (doc.exists) {
        let data = doc.data();
        for (const property in body) {
            data[property] = body[property]
        }
        let userRef = userDb.doc(username); 
        await userRef.set(data);
        delete data['password'];
        console.log(data);
        return res.status(200).json({
            "message": "User profile updated successfully",
            "data": data
        });
    }
    return res.status(404).json({
        "message": "username does not exist."
    });
});

//form submission for NGO verification
app.post('/form-submission-ngo', async(req,res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let username = body.username;
    let userDb = db.collection('Verification-Form');
    const donorRef = userDb.doc(username);
    if(donorRef.exists)
    {
        return res.status(403).json({
            "message": "Request already made and pending approval."
        });
    }
    await donorRef.set(body);
    return res.status(201).json({
        "message": "Verification Request Created Successfully."
    });
});

//form submission for company donor verification
app.post('/form-submission-company-donor', async(req,res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    
    let username = body.username;
    let userDb = db.collection('Verification-Form');
    const donorRef = userDb.doc(username);
    if(donorRef.exists)
    {
        return res.status(403).json({
            "message": "Request already made and pending approval."
        });
    }
    await donorRef.set(body);
    return res.status(201).json({
        "message": "Verification Request Created Successfully."
    });
});

//approve/reject for NGO
app.post('/verdict-submission-ngo', async(req,res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let verdict = body.verdict;
    let username = body.username;

    if(verdict === "accepted")
    {
        //update in user model
        let userDb = db.collection('User');
        let donorRef = userDb.doc(username);
        let donRefe = donorRef;
        donorRef = await donorRef.get();

        const verifDb = db.collection('Verification-Form');
        let verifRef = verifDb.doc(username);
        verifRef = await verifRef.get();
        verifRef = verifRef.data();

        let value = donorRef.data();
        value['isVerified'] = true;
        value['regNo'] = verifRef['registrationNumber'];
        value['approvalDocuments'] = verifRef['approvalDocuments'];
        await donRefe.set(value);
    }

    //delete instance from verification model
    const delVerifFormInstance = await db.collection('Verification-Form').doc(username).delete();

    return res.status(200).json({
        "message": "Approval status updated"
    });

});

//approve/reject for company donor
app.post('/verdict-submission-company-donor', async(req,res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let verdict = body.verdict;
    let username = body.username;

    if(verdict === "accepted")
    {
        //update in user model
        let userDb = db.collection('User');
        let donorRef = userDb.doc(username);
        let donRefe = donorRef;
        donorRef = await donorRef.get();

        const verifDb = db.collection('Verification-Form');
        let verifRef = verifDb.doc(username);
        verifRef = await verifRef.get();
        verifRef = verifRef.data();

        let value = donorRef.data();
        value['isVerified'] = true;
        value['regNo'] = verifRef['registrationNumber'];
        value['approvalDocuments'] = verifRef['approvalDocuments'];
        await donRefe.set(value);
    }

    //delete instance from verification model
    const delVerifFormInstance = await db.collection('Verification-Form').doc(username).delete();

    return res.status(200).json({
        "message": "Approval status updated"
    });

});

app.get('/get-give-outs/:username', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    const username = req.params.username;
    let coOrdinates;

    // check if username exists
    let userRef = db.collection('User').doc(username);
    const doc = await userRef.get();
    if (doc.exists) {
        let requiredGiveouts = [];
        let data = doc.data();
        coOrdinates = data['coOrdinates'];
        let radius = 250;
        const usersRef = db.collection('Give-Out-Applications');
        const snapshot = await usersRef.get();
        snapshot.forEach(async(doc) => {
            let data = doc.data();
            let theOtherCoOrdinates = data['coOrdinates'];
            let dist = ((haversine(coOrdinates, theOtherCoOrdinates))/1000);
            console.log(dist);
            console.log(theOtherCoOrdinates, coOrdinates);
            if(dist <= radius)
            {
                const todaysDate = new Date();
                let mdy = data['applyBy'].split("-");
                const theDate = new Date(parseInt(mdy[2]), parseInt(mdy[1])-1, parseInt(mdy[0]));
                if(theDate >= todaysDate)
                {
                    data['id'] = doc.id;
                    requiredGiveouts.push(data);
                }
            }
        });
        return res.status(200).json({
            "message": "Fetched Successfully",
            "count": requiredGiveouts.length,
            "data": requiredGiveouts
        });
    }
    return res.status(404).json({
        "message": "username does not exist."
    });
});

app.get('/get-donation-requests/:username', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    const username = req.params.username;
    let coOrdinates;

    // check if username exists
    let userRef = db.collection('User').doc(username);
    const doc = await userRef.get();
    if (doc.exists) {
        let requiredGiveouts = [];
        let data = doc.data();
        coOrdinates = data['coOrdinates'];
        let radius = 250;
        const usersRef = db.collection('Request-Donations-Applications');
        const snapshot = await usersRef.get();
        snapshot.forEach(async(doc) => {
            let data = doc.data();
            let theOtherCoOrdinates = data['coOrdinates'];
            let dist = ((haversine(coOrdinates, theOtherCoOrdinates))/1000);
            console.log(dist);
            if(dist <= radius)
            {
                const todaysDate = new Date();
                let mdy = data['applyBy'].split("-");
                const theDate = new Date(parseInt(mdy[2]), parseInt(mdy[1])-1, parseInt(mdy[0]));
                if(theDate >= todaysDate)
                {
                    data['id'] = doc.id;
                    requiredGiveouts.push(data);
                }
            }
        });
        return res.status(200).json({
            "message": "Fetched Successfully",
            "count": requiredGiveouts.length,
            "data": requiredGiveouts
        });
    }
    return res.status(404).json({
        "message": "username does not exist."
    });
});

app.get('/get-ngos/:username', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    const username = req.params.username;
    let sourceCoOrdinates;

    let userRef = db.collection('User').doc(username);
    const doc = await userRef.get();
    if (doc.exists) {
        sourceCoOrdinates = doc.data()['coOrdinates'];
    }
    console.log(sourceCoOrdinates);

    //we are getting user's co-ordinates and radius they selected
    
    let radius = 25;

    let requiredNGOs = [];

    const usersRef = db.collection('User');
    const snapshot = await usersRef.get();
        snapshot.forEach(doc => {
        let data = doc.data();
        if(data.type === 'NGO')
        {
            let pointCo = data.coOrdinates;
            let dist = ((haversine(sourceCoOrdinates, pointCo))/1000);
            if(dist <= radius)
            {
                delete data['password'];
                requiredNGOs.push(data);
            }
        }
    });
    return res.status(200).json({
        "message": "Fetched Successfully",
        "count": requiredNGOs.length,
        "data": requiredNGOs
    });
});

app.post('/request-for-donation', async(req, res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    /*
    {
    "username": "devang.k2",
    "title": "Clothes needed",
    "description": "Clothes for kids",
    "requirements": ["clothes", "cloth-material"],
    "documentsArray": ["www.google.com", "www.tinkle.com"],
    "applyBy": "10-12-2021",
    "coOrdinates": {
        "longitude": 73.81396316384317,
        "latitude": 18.63063063063063
    }
}
    */
    let username = body.username;
    let userDb = db.collection('Request-Donations-Applications');
    let donorRef = userDb.doc(username+'-'+translator.new());
    let applicationID = donorRef.id;
    body['id'] = applicationID;
    await donorRef.set(body);

    let initialMessage = [
        {
            "username": username,
            "message": "Kindly put your queries here."
        },
        {
            "username": username,
            "message": "We shall be more than happy to answer."
        },
    ]

    //creating instance of forum
    userDb = db.collection('Application-Forum');
    donorRef = userDb.doc(applicationID);
    await donorRef.set({
        "thread": initialMessage,
        "applicationID": applicationID,
        "admin": username
    });

    return res.status(201).json({
        "message": "Application Created Successfully"
    });
});

app.get('/particular-donation-request/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    let userDb = db.collection('Request-Donations-Applications');
    let userRef = userDb.doc(req.params.id);
    const doc = await userRef.get();
    if (doc.exists) {
        let data = doc.data();
        data['id'] = doc.id;
        return res.status(200).json(data);
    }
    return res.status(404).json({
        "message": "request ID does not exist."
    });
});

app.put('/particular-donation-request/:id', async(req, res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    let userDb = db.collection('Request-Donations-Applications');
    const donorRef = userDb.doc(req.params.id);
    const doc = await donorRef.get();
    if (doc.exists) {
        await donorRef.set(body);
        return res.status(200).json({
            "message": "Application Updated Successfully"
        });
    }
    return res.status(404).json({
        "message": "request ID does not exist."
    });
});

app.delete('/particular-donation-request/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }


    let userDb = db.collection('Request-Donations-Applications');
    let userRef = userDb.doc(req.params.id);
    let doc = await userRef.get();
    if (doc.exists) {
        userRef = userDb.doc(req.params.id).delete(); 
    }
    else
    {
        return res.status(404).json({
            "message": "request ID does not exist."
        });
    }

    let instancesToDelete = [];

    const usersRef = db.collection('Donor-Give-Out-Applications');
    const snapshot = await usersRef.get();
        snapshot.forEach(doc => {
        let data = doc.data();
        if(req.params.id === data['giveoutID'])
        {
            instancesToDelete.push(doc.id);
        }
    });

    console.log(instancesToDelete);

    userDb = db.collection('Donor-Give-Out-Applications');
    for(let i=0; i<instancesToDelete.length; i++)
    {
        userRef = userDb.doc(instancesToDelete[i]).delete();
    }

    userDb = db.collection('Application-Forum');
    userRef = userDb.doc(req.params.id).delete();

    return res.status(200).json({
        "message": "Request Deleted Successfully"
    });
});

app.get('/donation-requests/:username', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let requiredRequests = [];

    const usersRef = db.collection('Request-Donations-Applications');
    const snapshot = await usersRef.get();
        snapshot.forEach(doc => {
        let data = doc.data();
        if(data.username === req.params.username)
        {
            data['id'] = doc.id
            requiredRequests.push(data)
        }
    });

    return res.status(200).json({
        "message": "Fetched Successfully",
        "count": requiredRequests.length,
        "data": requiredRequests
    });
});

app.post('/give-out-donation', async(req, res)=> {
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    /*
    {
        "username": "devang.k2",
        "title": "Clothes needed",
        "description": "Clothes for kids",
        "available-material": ["100unit shirts", "500m cloth-material"],
        "documentsArray": ["www.google.com", "www.tinkle.com"],
        "applyBy": "10-12-2021",
        "coOrdinates": {
            "longitude": 73.81396316384317,
            "latitude": 18.63063063063063
        }
    }
    */
    let username = body.username;
    let userDb = db.collection('Give-Out-Applications');
    let donorRef = userDb.doc(username+'-'+translator.new());
    let applicationID = donorRef.id;
    body['id'] = applicationID;
    await donorRef.set(body);

    //creating instance of forum
    userDb = db.collection('Application-Forum');
    donorRef = userDb.doc(applicationID);
    await donorRef.set({
        "thread": [],
        "applicationID": applicationID,
        "admin": username
    });

    return res.status(201).json({
        "message": "Application Created Successfully",
        "id": donorRef.id
    });
});

app.get('/particular-give-out/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    let userDb = db.collection('Give-Out-Applications');
    let userRef = userDb.doc(req.params.id);
    const doc = await userRef.get();
    if (doc.exists) {
        let data = doc.data();
        data['id'] = doc.id;
        return res.status(200).json(data);
    }
    return res.status(404).json({
        "message": "Give Out ID does not exist."
    });
});

app.put('/particular-give-out/:id', async(req, res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    let userDb = db.collection('Give-Out-Applications');
    const donorRef = userDb.doc(req.params.id);
    const doc = await donorRef.get();
    if (doc.exists) {
        await donorRef.set(body);
        return res.status(200).json({
            "message": "Application Updated Successfully"
        });
    }
    return res.status(404).json({
        "message": "Give Out ID does not exist."
    });
});

app.delete('/particular-give-out/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    let userDb = db.collection('Give-Out-Applications');
    let userRef = userDb.doc(req.params.id);
    const doc = await userRef.get();
    if (doc.exists) {
        userRef = userDb.doc(req.params.id).delete();
    }
    else
    {
        return res.status(404).json({
            "message": "Give Out ID does not exist."
        });
    }

    let instancesToDelete = [];

    const usersRef = db.collection('NGO-Request-Applications');
    const snapshot = await usersRef.get();
        snapshot.forEach(doc => {
        let data = doc.data();
        if(req.params.id === data['requestID'])
        {
            instancesToDelete.push(doc.id);
        }
    });

    console.log(instancesToDelete);

    userDb = db.collection('NGO-Request-Applications');
    for(let i=0; i<instancesToDelete.length; i++)
    {
        userRef = userDb.doc(instancesToDelete[i]).delete();
    }

    userDb = db.collection('Application-Forum');
    userRef = userDb.doc(req.params.id).delete();


    return res.status(200).json({
        "message": "Give Out Deleted Successfully"
    });
});

app.get('/donation-give-outs/:username', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let requiredRequests = [];

    const usersRef = db.collection('Give-Out-Applications');
    const snapshot = await usersRef.get();
        snapshot.forEach(doc => {
        let data = doc.data();
        if(data.username === req.params.username)
        {
            data['id'] = doc.id
            requiredRequests.push(data)
        }
    });

    return res.status(200).json({
        "message": "Fetched Successfully",
        "count": requiredRequests.length,
        "data": requiredRequests
    });
});

app.post('/add-comment/:applicationID', async(req, res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    /*
    {
        "username": "devang.k2",
        message: ""
    }
    We push this in thread array of forum
    */

    let userDb = db.collection('Application-Forum');
    const donorRef = userDb.doc(req.params.applicationID);
    const doc = await donorRef.get();
    if (doc.exists) {
        let data = doc.data();
        data.thread.push(body)
        await donorRef.set(data);
        return res.status(200).json({
            "message": "Comment Added Successfully"
        });
    }
    return res.status(404).json({
        "message": "application ID does not exist."
    });
});

app.get('/forum/:applicationID', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let userDb = db.collection('Application-Forum');
    let userRef = userDb.doc(req.params.applicationID);
    const doc = await userRef.get();
    if (doc.exists) {
        let data = doc.data();
        return res.status(200).json(data);
    }
    return res.status(404).json({
        "message": "Application ID does not exist."
    });
});

//donor applies to an NGO (POST GET DELETE UPDATE - only one application per username)
app.post('/apply-to-donation-request', async(req, res)=>{
    /*
    {
        "username": "",
        "requestID": "",
        "title": "",
        "body": "",
        "documents": []
    }
    */
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let username = body.username;
    let requestID = body.requestID;
    let userDb = db.collection('NGO-Request-Applications');
    let donorRef = userDb.doc(username+'-'+requestID);
    const doc = await donorRef.get();
    if (doc.exists) {
        return res.status(403).json({
            "message": "Application already created."
        });
    }
    body['status'] = "Pending";
    await donorRef.set(body);

    return res.status(201).json({
        "message": "Application Sent Successfully",
        "id": donorRef.id
    });
});

app.get('/donation-application/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let userDb = db.collection('NGO-Request-Applications');
    let userRef = userDb.doc(req.params.id);
    const doc = await userRef.get();
    if (doc.exists) {
        let data = doc.data();
        return res.status(200).json(data);
    }
    return res.status(404).json({
        "message": "ID does not exist."
    });
});

app.put('/donation-application/:id', async(req, res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    let userDb = db.collection('NGO-Request-Applications');
    const donorRef = userDb.doc(req.params.id);
    const doc = await donorRef.get();
    if (doc.exists) {
        await donorRef.set(body);
        return res.status(200).json({
            "message": "Application Updated Successfully"
        });
    }
    return res.status(404).json({
        "message": "ID does not exist."
    });
});

app.delete('/donation-application/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    let userDb = db.collection('NGO-Request-Applications');
    let userRef = userDb.doc(req.params.id);
    const doc = await userRef.get();
    if (doc.exists) {
        userRef = userDb.doc(req.params.id).delete();
        return res.status(200).json({
            "message": "Application Deleted Successfully"
        });
    }
    return res.status(404).json({
        "message": "ID does not exist."
    });
});

app.post('/apply-to-donor-give-out', async(req, res)=>{
    /*
    {
        "username": "",
        "giveoutID": "",
        "title": "",
        "body": "",
        "documents": []
    }
    */
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let username = body.username;
    let giveoutID = body.giveoutID;
    let userDb = db.collection('Donor-Give-Out-Applications');
    let donorRef = userDb.doc(username+'-'+giveoutID);
    const doc = await donorRef.get();
    if (doc.exists) {
        return res.status(403).json({
            "message": "Application already created."
        });
    }
    body['status'] = "Pending";
    await donorRef.set(body);

    return res.status(201).json({
        "message": "Application Sent Successfully",
        "id": donorRef.id
    });
});

app.get('/give-out-application/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let userDb = db.collection('Donor-Give-Out-Applications');
    let userRef = userDb.doc(req.params.id);
    const doc = await userRef.get();
    if (doc.exists) {
        let data = doc.data();
        return res.status(200).json(data);
    }
    return res.status(404).json({
        "message": "ID does not exist."
    });
});

app.put('/give-out-application/:id', async(req, res)=>{
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    let userDb = db.collection('Donor-Give-Out-Applications');
    const donorRef = userDb.doc(req.params.id);
    const doc = await donorRef.get();
    if (doc.exists) {
        await donorRef.set(body);
        return res.status(200).json({
            "message": "Application Updated Successfully"
        });
    }
    return res.status(404).json({
        "message": "ID does not exist."
    });
});

app.delete('/give-out-application/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }
    let userDb = db.collection('Donor-Give-Out-Applications');
    let userRef = userDb.doc(req.params.id);
    const doc = await userRef.get();
    if (doc.exists) {
        userRef = userDb.doc(req.params.id).delete();
        return res.status(200).json({
            "message": "Application Deleted Successfully"
        });
    }
    return res.status(404).json({
        "message": "ID does not exist."
    });
});

app.get('/applications-applied-to-by-an-ngo/:username', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let requiredInstances = [];

    const usersRef = db.collection('NGO-Request-Applications');
    const snapshot = await usersRef.get();
    snapshot.forEach(doc => {
        let data = doc.data();
        if(data.username === req.params.username)
        {
            requiredInstances.push(data);
        }
    });

    return res.status(200).json({
        "count": requiredInstances.length,
        "data": requiredInstances,
        "message": "Fetched Successfully",
    })
});

app.get('/applications-applied-to-by-donor/:username', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let requiredInstances = [];

    const usersRef = db.collection('Donor-Give-Out-Applications');
    const snapshot = await usersRef.get();
    snapshot.forEach(doc => {
        let data = doc.data();
        if(data.username === req.params.username)
        {
            requiredInstances.push(data);
        }
    });

    return res.status(200).json({
        "count": requiredInstances.length,
        "data": requiredInstances,
        "message": "Fetched Successfully",
    })
});

// All received applications (NGO)
app.get('/all-received-applications-for-ngo/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let requiredInstances = [];

    const usersRef = db.collection('NGO-Request-Applications');
    const snapshot = await usersRef.get();
    snapshot.forEach(doc => {
        let data = doc.data();
        if(data.requestID === req.params.id)
        {
            requiredInstances.push(data);
        }
    });

    return res.status(200).json({
        "count": requiredInstances.length,
        "data": requiredInstances,
        "message": "Fetched Successfully",
    })
});

// All received applications (Company)
app.get('/all-received-applications-for-donor/:id', async(req, res)=>{
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let requiredInstances = [];

    const usersRef = db.collection('Donor-Give-Out-Applications');
    const snapshot = await usersRef.get();
    snapshot.forEach(doc => {
        let data = doc.data();
        if(data.giveoutID === req.params.id)
        {
            requiredInstances.push(data);
        }
    });

    return res.status(200).json({
        "count": requiredInstances.length,
        "data": requiredInstances,
        "message": "Fetched Successfully",
    })
});

app.post('/ngo-application-pass-verdict/:id', async(req, res)=>{
    /*
    {
        "verdict": "accepted/rejected"
    }
    */
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let verdict = body.verdict;
    let userDb = db.collection('NGO-Request-Applications');
    let donorRef = userDb.doc(req.params.id);
    const doc = await donorRef.get();
    if (doc.exists) {
        let data = doc.data();
        if(verdict === "accepted")
        {
            data['status'] = "Accepted";
            data['completedBy'] = [];
        }
        else if(verdict === "rejected")
        {
            data['status'] = "Rejected"
        }
        await donorRef.set(data);
        return res.status(201).json({
            "message": "Status Updated successfully."
        });
    }
    return res.status(404).json({
        "message": "ID does not exist",
    });
});

app.post('/company-application-pass-verdict/:id', async(req, res)=>{
    /*
    {
        "verdict": "accepted/rejected"
    }
    */
    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let verdict = body.verdict;
    let userDb = db.collection('Donor-Give-Out-Applications');
    let donorRef = userDb.doc(req.params.id);
    const doc = await donorRef.get();
    if (doc.exists) {
        let data = doc.data();
        if(verdict === "accepted")
        {
            data['status'] = "Accepted";
            data['completedBy'] = [];
        }
        else if(verdict === "rejected")
        {
            data['status'] = "Rejected"
        }
        await donorRef.set(data);
        return res.status(201).json({
            "message": "Status Updated successfully."
        });
    }
    return res.status(404).json({
        "message": "ID does not exist",
    });
});

app.post('/transaction-completion-side-donor-giveout', async(req, res)=>{
    /*
    {
        "id": "",
        "username": ""
    }
    */

    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let isTransactionComplete = false;

    let userDb = db.collection('NGO-Request-Applications');
    let donorRef = userDb.doc(body['id']);
    const doc = await donorRef.get();

    let theData;

    if (doc.exists) {
        let data = doc.data();
        data['completedBy'].push(body['username']);
        var set = new Set(data['completedBy']);
        data['completedBy'] = [...set]
        console.log(data['completedBy'])
        if(data['completedBy'].length === 2)
        {
            data['status'] = 'Completed';
            var today = new Date();
            var dd = String(today.getDate()).padStart(2, '0');
            var mm = String(today.getMonth() + 1).padStart(2, '0'); //January is 0!
            var yyyy = today.getFullYear();
            today = dd + '-' + mm + '-' + yyyy;
            data['completionDate'] = today;
            data['link'] = "https://sahayya-public-invoice.netlify.app/invoice/"+doc.id;
            isTransactionComplete = false
            theData = data;

            await donorRef.set(data);

            userDb = db.collection('Transaction-Completion-Invoice');
            donorRef = userDb.doc(body['id']);

            let otherDB = db.collection('User');
            let otherRef = otherDB.doc(data['completedBy'][0]);
            let doc2 = await otherRef.get();

            let user1 = doc2.data();

            otherDB = db.collection('User');
            otherRef = otherDB.doc(data['completedBy'][1]);
            doc2 = await otherRef.get();

            let user2 = doc2.data();

            let theGiveoutID = data['requestID'];
            otherDB = db.collection('Give-Out-Applications');
            otherRef = otherDB.doc(theGiveoutID);
            doc2 = await otherRef.get();

            let requestData = doc2.data();

            donorRef.set({
                "type": "Donor donated to an NGO on their Giveout",
                "applicationData": theData,
                "dataOfPersonWhoApplied": (user1['username'] === theData['username']) ? user1 : user2,
                "dataOfPersonWhoCreatedRequest": (user1['username'] === theData['username']) ? user2 : user1,
                "requestData": requestData,
            });

        }
        else
        {
            await donorRef.set(data);
        }

        return res.status(201).json({
            "message": "Status Updated successfully."
        });
    }
    return res.status(404).json({
        "message": "ID does not exist",
    });
});


app.post('/transaction-completion-side-ngo-request', async(req, res)=>{
    /*
    {
        "id": "",
        "username": ""
    }
    */

    let body = req.body;
    let token = req.headers['authorization'];

    if(!validateJWT(token))
    {
        return res.status(401).json({
            "message": "Invalid token"
        });
    }

    let isTransactionComplete = false;

    let userDb = db.collection('Donor-Give-Out-Applications');
    let donorRef = userDb.doc(body['id']);
    let doc = await donorRef.get();

    let theData;

    if (doc.exists) {
        let data = doc.data();
        data['completedBy'].push(body['username']);
        var set = new Set(data['completedBy']);
        data['completedBy'] = [...set]
        console.log(data['completedBy'])
        if(data['completedBy'].length === 2)
        {
            data['status'] = 'Completed';
            var today = new Date();
            var dd = String(today.getDate()).padStart(2, '0');
            var mm = String(today.getMonth() + 1).padStart(2, '0'); //January is 0!
            var yyyy = today.getFullYear();
            today = dd + '-' + mm + '-' + yyyy;
            data['completionDate'] = today;
            data['link'] = "https://sahayya-public-invoice.netlify.app/invoice/"+doc.id;
            isTransactionComplete = false
            theData = data;

            await donorRef.set(data);
            userDb = db.collection('Transaction-Completion-Invoice');
            donorRef = userDb.doc(body['id']);

            let otherDB = db.collection('User');
            let otherRef = otherDB.doc(data['completedBy'][0]);
            let doc2 = await otherRef.get();

            let user1 = doc2.data();

            otherDB = db.collection('User');
            otherRef = otherDB.doc(data['completedBy'][1]);
            doc2 = await otherRef.get();

            let user2 = doc2.data();

            let theGiveoutID = data['giveoutID'];
            otherDB = db.collection('Request-Donations-Applications');
            otherRef = otherDB.doc(theGiveoutID);
            doc2 = await otherRef.get();

            let requestData = doc2.data();

            donorRef.set({
                "type": "Donor donated to NGO Request",
                "applicationData": theData,
                "dataOfPersonWhoApplied": (user1['username'] === theData['username']) ? user1 : user2,
                "dataOfPersonWhoCreatedRequest": (user1['username'] === theData['username']) ? user2 : user1,
                "requestData": requestData,
            });

        }
        else{
            await donorRef.set(data);
        }
        
        //make a new table instance
        //give it a type
        //give it data of request
        //data of donor/ngo who's app
        //the application
        //data of user who made the req

        

        return res.status(201).json({
            "message": "Status Updated successfully."
        });
    }
    return res.status(404).json({
        "message": "ID does not exist",
    });

});

app.get('/invoice/:id', async(req, res)=>{
    let id = req.params.id;

    // check if id exists
    let userRef = db.collection('Transaction-Completion-Invoice').doc(id);
    const doc = await userRef.get();
    if (doc.exists) {
        let data = doc.data();
        return res.status(200).json(data);
    }
    return res.status(404).json({
        "message": "ID does not exist."
    });
})



// Donor Claims Donation Done 
// To an approved application 
// applied by donor


// Donor Claims Donation Done 
// To an approved application 
// applied by NGO


// NGO Claims Donation Done 
// To an approved application 
// applied by Donor
// Generate Downloadable Certificate


// NGO Claims Donation Done 
// To an approved application 
// applied by NGO
// Generate Downloadable Certificate


exports.api = functions
    .region('asia-south1')
    .https.onRequest(app)


// app.listen(port, () => {
//     console.log(`Example app listening at http://localhost:${port}`)
// });