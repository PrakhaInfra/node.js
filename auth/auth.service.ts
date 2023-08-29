import { Injectable, NotFoundException, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import * as nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
import { JwtService } from '@nestjs/jwt';
// import { JwtModule } from './jwt/jwt.module';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class AuthService {
  private readonly verificationTokens: Map<string, string> = new Map();
  private readonly resetPasswordTokens: Map<string, string> = new Map();

  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
    
  ) {}

  async createUser(createUserDto: CreateUserDto): Promise<User> {
    const { username, password } = createUserDto;

    const existingUser = await this.usersRepository.findOne({ where: { username } });
    if (existingUser) {
      throw new BadRequestException('Username already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User();
    user.username = username;
    user.password = hashedPassword;

    const savedUser = await this.usersRepository.save(user);
    this.sendVerificationEmail(savedUser.username, savedUser.verificationToken);
    this.sendWelcomeEmail(savedUser.username);


    return savedUser;
  }

  async sendVerificationEmail(username: string, token: string): Promise<void> {
    const verificationLink = `https://localhost:5555/verify/${token}`;


    const transporter = nodemailer.createTransport({
      service: 'outlook',
      auth: {
        user: 'ppandey@infrablok.com',
        pass: 'Honeyinfra@1941',
      },
    });

    const mailOptions = {
      from: 'ppandey@infrablok.com',
      to: 'prakharpandey150@gmail.com',
      subject: 'Verify Your Email',
      text: `Click the following link to verify your email: ${verificationLink}`,
      html: `<p>Click the following link to verify your email: <a href="${verificationLink}">${verificationLink}</a></p>`,
    };

    await transporter.sendMail(mailOptions);
  }

  async sendWelcomeEmail(username: string): Promise<void> {
    const transporter = nodemailer.createTransport({
      service: 'outlook',
      auth: {
        user: 'ppandey@infrablok.com',
        pass: 'Honeyinfra@1941',
      },
    });

    const mailOptions = {
      from: 'ppandey@infrablok.com',
      to: 'prakharpandey150@gmail.com',
      subject: 'Welcome to Our App!',
      text: 'Thank you for signing up on our app.',
      html: '<p>Thank you for signing up on our app.</p>',
    };

    await transporter.sendMail(mailOptions);
  }



  async verifyUser(token: string): Promise<{ message: string }> {
    const username = Array.from(this.verificationTokens.keys()).find(
      (key) => this.verificationTokens.get(key) === token,
    );

    if (!username) {
      throw new BadRequestException('Invalid verification token');
    }

    const user = await this.usersRepository.findOne({ where: { username } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    user.verified = true;
    await this.usersRepository.save(user);
    this.verificationTokens.delete(username);

    return { message: 'Email verified successfully' };
  }

  async sendPasswordResetEmail(username: string): Promise<{ message: string }> {
    const user = await this.usersRepository.findOne({ where: { username } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const resetToken = uuidv4();
    this.resetPasswordTokens.set(username, resetToken);

    const resetLink = `https://localhost:5555.com/reset-password/${resetToken}`;


    const transporter = nodemailer.createTransport({
      service: 'outlook',
      auth: {
        user: 'ppandey@infrablok.com',
        pass: 'Honeyinfra@1941',
      },
    });

    const mailOptions = {
      from: 'ppandey@infrablok.com',
      to: 'prakharpandey150@gmail.com',
      subject: 'Password Reset Request',
      text: `Click the following link to reset your password: ${resetLink}`,
      html: `<p>Click the following link to reset your password: <a href="${resetLink}">${resetLink}</a></p>`,
    };

    await transporter.sendMail(mailOptions);

    return { message: 'Password reset email sent successfully' };
  }

  async resetPassword(username: string, newPassword: string, token: string): Promise<{ message: string }> {
    const storedToken = this.resetPasswordTokens.get(username);

    if (storedToken !== token) {
      throw new NotFoundException('Token not found or expired');
    }

    const user = await this.usersRepository.findOne({ where: { username } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    await this.usersRepository.save(user);
    this.resetPasswordTokens.delete(username);

    return { message: 'Password reset successful' };
  }

  async getUserDetails(username: string): Promise<User | undefined> {
    return this.usersRepository.findOne({ where: { username } });
  }

  async updateUserDetails(username: string, updates: UpdateUserDto): Promise<User> {
    const user = await this.usersRepository.findOne({ where: { username } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (updates.password) {
      updates.password = await bcrypt.hash(updates.password, 10);
    }

    Object.assign(user, updates);
    await this.usersRepository.save(user);

    return user;
  }

  async login(loginDto: LoginDto): Promise<{ accessToken: string }> {
    const { username, password } = loginDto;
    const user = await this.validateUser(username, password);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { username: user.username, sub: user.id };
    const accessToken = this.jwtService.sign(payload);

    return { accessToken };
  }

  private async validateUser(username: string, password: string): Promise<User | null> {
    const user = await this.usersRepository.findOne({ where: { username } });

    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }

    return null;
  }
}
