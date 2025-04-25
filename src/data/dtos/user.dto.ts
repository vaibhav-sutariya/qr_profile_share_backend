export interface IUserDto {
	name: string;
	email: string;
	password: string;
	passwordConfirm: string;
	role?: string;
	authType?: string;
}
