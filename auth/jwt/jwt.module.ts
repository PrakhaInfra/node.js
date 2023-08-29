

import { Module } from '@nestjs/common';
import { JwtModule as NestJwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    NestJwtModule.register({
      secret: 'infra', 
      signOptions: { expiresIn: '1d' }, 
    }),
  ],
  providers: [JwtStrategy],
  exports: [NestJwtModule],
})
export class JwtModule {}
