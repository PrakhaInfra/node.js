// src/auth/auth.module.ts

import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '../auth/jwt/jwt.module';


@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    JwtModule, 
  ],
  providers: [AuthService],
  controllers: [AuthController],
})
export class AuthModule {}
