class Organization {

  //  Either domain or name is required. Both may be specified. 
  name?: string;
  domain?: string;
  sfinUrl: string;
  url?: string;
  id?: string;

  constructor(data: {
    domain?: string,
    sfinUrl: string,
    name?: string,
    url?: string,
    id?: string
  }) {
    this.domain = data.domain;
    this.sfinUrl = data.sfinUrl;
    this.name = data.name;
    this.url = data.url;
    this.id = data.id;
  }

  static fromJson(json: string): Organization {
    const data = JSON.parse(json);
    return new Organization(data);
  }
}

export default Organization;