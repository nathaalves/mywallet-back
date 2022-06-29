import express from 'express';
import cors from 'cors';
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';
import joi from 'joi';
import bcrypt from 'bcrypt';
import { v4 as uuid } from 'uuid';

dotenv.config();

const server = express();
server.use(cors());
server.use(express.json());

const client = new MongoClient(process.env.URL_CONNECT_MONGO);
let db = null;

async function startConectionToDB () {
    await client.connect();
    db = client.db('my-wallet');
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
        if (!user) return response.status(401).send('Email ou senha inválidos!');

        const isValidPw = bcrypt.compareSync(password, user.encryptedPw);
        if (!isValidPw) return response.status(401).send('Email ou senha inválidos!');
        
        const token = uuid();

        await db.collection('sessions').insertOne({
            _id: user._id,
            token
        });
        
        response.status(202).send('Login efetuado com sucesso!');
        
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

    const { value, description } = request.body;

    const cashFlowSchema = joi.object({
        value: joi.string().required(),
        description: joi.string().required()
    });

    const { error } = cashFlowSchema.validate( request.body );
    if (error) return response.status(406).send(error.description.message)

    const authorization = request.header('Authorization');
    const token = authorization?.replace('Bearer ', '');
    if(!token) return response.status(401).send('Usuário não autorizado!');

    try {

        await startConectionToDB();

        const session = await db.collection("sessions").findOne({ token });
        console.log(session)
        if (!session) return response.status(404).send('Usuário não encontrado!');

        db.collection('cash-flow').insertOne({ _id: session._id , value, description });

        response.status(201).send('Registro criado com sucesso!');
        client.close();

    } catch (error) {
        response.status(500).send('Erro do servidor!');
        client.close();
    }
});


server.listen(process.env.PORT)


