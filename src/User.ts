import mongoose, { Schema } from 'mongoose';

const UserSchema = new Schema(
  {
    workspaceId: {
      // type: mongoose.Schema.Types.ObjectId,
      type: String,
    },
    name: String,
    password: {
      type: String,
      required: true,
    },
    email: String,
    document_type: {
      type: String,
      enum: ['cnpj', 'cpf'],
    },
    document_number: {
      type: Number,
      max: 14,
    },
    role: {
      type: String,
      enum: ['admin', 'user'],
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model('User', UserSchema);
