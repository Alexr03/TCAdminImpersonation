DELETE FROM tc_site_map WHERE controller LIKE 'Impersonation';

DELETE FROM tc_permissions WHERE permission_id LIKE '1060';
DELETE FROM tc_role_permissions WHERE permission_id LIKE '1060';

DELETE FROM tc_page_icons WHERE icon_id LIKE '1060';