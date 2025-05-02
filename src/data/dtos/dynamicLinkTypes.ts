export interface IDynamicLinkRequest {
	id: string;
	name: string;
	email: string;
	photo?: string;
	position: string;
	location: string;
}

export interface IDynamicLinkResponse {
	status: string;
	link: string;
}
