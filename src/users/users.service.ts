import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { User } from './user.entity';

@Injectable()
export class UsersService {
  private users: User[] = [
    {
      id: 1,
      username: 'test',
      password: bcrypt.hashSync('test', 10), // 비밀번호를 해시하여 저장
    },
  ];


  async create(username: string, password: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser: User = { id: Date.now(), username, password: hashedPassword };
    this.users.push(newUser);
    return newUser;
  }

  async findByUsername(username: string): Promise<User | undefined> {
    return this.users.find(user => user.username === username);
  }

  async updateRefreshToken(userId: number, refreshToken: string): Promise<void> {
    const user = this.users.find(user => user.id === userId);
    if (user) {
      user.refreshToken = refreshToken;
    }
  }
}
