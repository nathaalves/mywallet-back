import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId } from 'mongodb';
import dotenv from 'dotenv';
import joi from 'joi';
import bcrypt from 'bcrypt';
import { v4 as uuid } from 'uuid';
import dayjs from 'dayjs';

dotenv.config();

const server = express();
server.use(cors());
server.use(express.json());

const client = new MongoClient(process.env.URI_CONNECT_MONGO);
let db = null;

async function startConectionToDB () {
    await client.connect();
    db = client.db(process.env.MONGO_DB_NAME);
};

server.post('/login', async (request, response) => {

    const { email, password } = request.body;

    const loginSchema = joi.object({
        email: joi.string().email().required(),
        password: joi.string().required()
    });

    const { error } = loginSchema.validate( request.body );
    if (error) return response.status(400).send(error.details[0].message);

    try {
        
        await startConectionToDB();
        
        const user = await db.collection('users').findOne({ email });
        if (!user) return response.status(401).send('Usuário não cadastrado!');
        
        const isValidPw = bcrypt.compareSync(password, user.encryptedPw);
        if (!isValidPw) return response.status(401).send('Email ou senha inválidos!');
        
        const token = uuid();
        
        const session = {
            userId: user._id,
            userName: user.name,
            token
        };
        
        await db.collection('sessions').insertOne(session);
        
        response.status(202).send(session);
        client.close();

    } catch (error) {
        response.status(500).send('Erro do servidor!');
        client.close();
    };
});

server.post( '/registration', async (request, response) => {

    const { name, email, password, pwConfirm } = request.body;

    const registrationSchema = joi.object({
        name: joi.string().required(),
        email: joi.string().email().required(),
        password: joi.string().required(),
        pwConfirm: joi.string().required()
    });

    const { error } = registrationSchema.validate(request.body);
    if (error) return response.status(400).send(error.details[0].message);

    try {

        await startConectionToDB();

        const user = await db.collection('users').findOne({ email });
        if (user) return response.status(409).send('Usuário já cadastrado!');
        if (password !== pwConfirm) return response.status(409).send('Confirme a senha informada!');

        const encryptedPw = bcrypt.hashSync(password, 10);

        await db.collection('users').insertOne({
            name,
            email,
            encryptedPw
        });
        
        response.status(201).send('Usuário cadastrado com sucesso!');
        client.close();

    } catch ( error ) {

        response.status(500).send('Erro do servidor!');
        client.close();
    };
});

server.post('/cash-flow', async (request, response) => {

    const cashFlowSchema = joi.object({
        value: joi.string().required(),
        description: joi.string().required(),
        type: joi.string().valid('cash-in', 'cash-out').required()
    });

    const { error } = cashFlowSchema.validate( request.body );
    if (error) return response.status(406).send(error.details[0].message)

    const { authorization } = request.headers;
    const token = authorization?.replace('Bearer ', '');
    if(!token) return response.status(401).send('Usuário não autorizado!');

    try {

        await startConectionToDB();
        
        const session = await db.collection("sessions").findOne({ token });
        if (!session) return response.status(404).send('Usuário não encontrado!');
        
        await db.collection('cash_flow').insertOne({
            ...request.body,
            userId: session.userId, 
            date: dayjs().format('YYYY/MM/DD HH:mm:ss') 
        });
        
        response.status(201).send('Registro criado com sucesso!');
        
        client.close();
        
    } catch (error) {
        response.status(500).send(error);
        client.close();
    }; 
});

server.get('/cash-flow', async (request, response) => {

    const { authorization } = request.headers;
    const token = authorization?.replace('Bearer ', '');
    if(!token) return response.status(401).send('Usuário não autorizado!');
    
    try {
        
        await startConectionToDB();
        
        const session = await db.collection("sessions").findOne({ token });
        if (!session) return response.status(404).send('Usuário não encontrado!');
        
        let cashFlow = await db.collection('cash_flow').find({ userId: session.userId }).toArray();
        cashFlow.sort( (b, a) => {
            if (a.date > b.date) {
              return 1;
            }
            if (a.date < b.date) {
              return -1;
            }
            return 0;
        });

        response.send(cashFlow)
        client.close()

    } catch (error) {
        response.status(500).send('Erro do servidor!')
        client.close();
    };
});

server.post('/session', async (request, response) => {

    const { authorization } = request.headers;
    const token = authorization?.replace('Bearer ', '');
    if(!token) return response.status(401).send('Usuário não autorizado!');

    try {

        await startConectionToDB();
        
        const session = await db.collection("sessions").findOne({ token });
        if (!session) return response.status(404).send('Usuário não encontrado!');
        
        response.sendStatus(200);
        client.close();

    } catch (error) {
        response.status(500).send('Erro do servidor!')
        client.close();
    };
});

server.delete('/session', async (request, response) => {

    const { authorization } = request.headers;
    const token = authorization?.replace('Bearer ', '');
    if(!token) return response.status(401).send('Usuário não autorizado!');

    try {

        await startConectionToDB();
        
        const session = await db.collection("sessions").findOne({ token });
        if (!session) return response.status(404).send('Usuário não encontrado!');

        await db.collection("sessions").deleteOne({ token });
        
        response.sendStatus(200);
        client.close();

    } catch (error) {
        response.status(500).send('Erro do servidor!')
        client.close();
    };
});

server.delete('/cash-flow/:id', async (request, response) => {

    const { authorization } = request.headers;
    const token = authorization?.replace('Bearer ', '');
    if(!token) return response.status(401).send('Usuário não autorizado!');

    const { id } = request.params;
    
    try {
        
        await startConectionToDB();
        
        const session = await db.collection("sessions").findOne({ token });
        if (!session) return response.status(404).send('Usuário não encontrado!');
        
        const cashFlow = await db.collection('cash_flow').findOne({ _id: ObjectId(id) });
        if (!cashFlow) return response.status(404).send('Registro não encontrado');
        
        await db.collection("cash_flow").deleteOne({ _id: ObjectId(id) });
        
        response.sendStatus(200);
        client.close();

    } catch (error) {
        response.status(500).send('Erro do servidor!')
        client.close();
    };
});

server.listen(process.env.PORT);