import { Entity, ObjectIdColumn, ObjectId, Column } from 'typeorm';

@Entity('email_otps')
export class EmailOtp {
  @ObjectIdColumn()
  _id: ObjectId;

  @Column()
  email: string;

  @Column()
  otpHash: string;

  @Column()
  expiresAt: Date;

  @Column({ default: false })
  verified: boolean;

  @Column()
  createdAt: Date;

  @Column({ default: 0 })
  resendCount: number;

  @Column({ default: 0 })
  attemptCount: number;

  @Column()
  lastResendAt: Date;
}
