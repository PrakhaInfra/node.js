// src/app.module.ts

import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { JwtModule } from './auth/jwt/jwt.module';
import { User } from './auth/entities/user.entity';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres', 
      host: 'localhost',
      port: 5432,
      username: 'postgres',
      password: 'Honey@41',
      database: 'demo',
      entities: [User],
      synchronize: true,
      
    }),
AuthModule,
  JwtModule, 
  ],
})
export class AppModule { }

