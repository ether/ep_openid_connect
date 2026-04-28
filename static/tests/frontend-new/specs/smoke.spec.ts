import {expect, test} from '@playwright/test';
import {getPadBody, goToNewPad} from 'ep_etherpad-lite/tests/frontend-new/helper/padHelper';

test.beforeEach(async ({page}) => {
  await goToNewPad(page);
});

test.describe('ep_openid_connect', () => {
  test('pad loads with plugin installed', async ({page}) => {
    const padBody = await getPadBody(page);
    await expect(padBody).toBeVisible();
  });
});
