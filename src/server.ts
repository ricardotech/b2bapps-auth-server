import mongoose from 'mongoose';
import express from 'express';
import cors from 'cors';

import AuthRoutes from './routes';

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: '*' }));

app.use('/', AuthRoutes);

const user = process.env.DB_USER;
const password = process.env.DB_PASSWORD;
const database = process.env.DB_DATABASE;
const server = `mongodb+srv://${user}:${password}@cluster.w2thyu4.mongodb.net/${database}?retryWrites=true&w=majority`;

mongoose.connect(server).then(() => {
  console.log('Database connection successfully!');
});

app.listen(3333, () => console.log('Server is running on port 3333'));
