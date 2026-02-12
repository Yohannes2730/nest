import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type RefreshTokenDocument = HydratedDocument<RefreshToken>;

@Schema({ versionKey: false, timestamps: true })
export class RefreshToken {
  @Prop({ required: true })
  token: string;

  @Prop({ type: Types.ObjectId, ref: 'User', required: true })
  userId: Types.ObjectId;

  @Prop({ required: true })
  expiresAt: Date;
}

export const RefreshTokenSchema =
  SchemaFactory.createForClass(RefreshToken);
