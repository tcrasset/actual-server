import getAccountDb from '../../../account-db.js';
import { FileNotFound } from '../../errors.js';
import {
  FilesService,
  File,
  FileUpdate,
} from '../../services/files-service.js'; // Adjust the path as necessary
import crypto from 'node:crypto';
describe('FilesService', () => {
  let filesService;
  let accountDb;

  beforeAll((done) => {
    accountDb = getAccountDb();

    accountDb.mutate(
      'INSERT INTO files (id, group_id, sync_version, name, encrypt_meta, encrypt_salt, encrypt_test, encrypt_keyid, deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        '1',
        'group1',
        1,
        'file1',
        '{"key":"value"}',
        'salt',
        'test',
        'keyid',
        0,
      ],
    );

    filesService = new FilesService(accountDb);
    done();
  });

  test('get should return a file', () => {
    const file = filesService.get('1');
    const expectedFile = new File({
      id: '1',
      groupId: 'group1',
      syncVersion: 1,
      name: 'file1',
      encryptMeta: '{"key":"value"}',
      encryptSalt: 'salt',
      encryptTest: 'test',
      encryptKeyId: 'keyid',
      deleted: false,
    });

    expect(file).toEqual(expectedFile);
  });

  test('get should throw FileNotFound if file is deleted or does not exist', () => {
    const fileId = crypto.randomBytes(16).toString('hex');
    accountDb.mutate(
      'INSERT INTO files (id, group_id, sync_version, name, encrypt_meta, encrypt_salt, encrypt_test, encrypt_keyid, deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        fileId,
        'group1',
        1,
        'file1',
        '{"key":"value"}',
        'salt',
        'test',
        'keyid',
        1,
      ],
    );

    expect(() => {
      filesService.get(fileId);
    }).toThrow(FileNotFound);

    expect(() => {
      filesService.get(crypto.randomBytes(16).toString('hex'));
    }).toThrow(FileNotFound);
  });

  test.each([true, false])(
    'set should insert a new file with deleted: %p',
    (deleted) => {
      const fileId = crypto.randomBytes(16).toString('hex');
      const newFile = new File({
        id: fileId,
        groupId: 'group2',
        syncVersion: 1,
        name: 'file2',
        encryptMeta: '{"key":"value2"}',
        deleted: deleted,
      });

      filesService.set(newFile);

      const file = filesService.validate(filesService.getRaw(fileId));
      const expectedFile = new File({
        id: fileId,
        groupId: 'group2',
        syncVersion: 1,
        name: 'file2',
        encryptMeta: '{"key":"value2"}',
        encryptSalt: null, // default value
        encryptTest: null, // default value
        encryptKeyId: null, // default value
        deleted: deleted,
      });

      expect(file).toEqual(expectedFile);
    },
  );

  test('update should modify an existing file', () => {
    const fileUpdate = new FileUpdate({
      name: 'updatedFile1',
      groupId: 'updatedGroup1',
      encryptSalt: 'updatedSalt',
      encryptTest: 'updatedTest',
      encryptKeyId: 'updatedKeyId',
      encryptMeta: '{"key":"updatedValue"}',
      syncVersion: 2,
      deleted: true,
    });
    const updatedFile = filesService.update('1', fileUpdate);

    expect(updatedFile).toEqual(
      new File({
        id: '1',
        name: 'updatedFile1',
        groupId: 'updatedGroup1',
        encryptSalt: 'updatedSalt',
        encryptTest: 'updatedTest',
        encryptMeta: '{"key":"updatedValue"}',
        encryptKeyId: 'updatedKeyId',
        syncVersion: 2,
        deleted: true,
      }),
    );
  });
});
