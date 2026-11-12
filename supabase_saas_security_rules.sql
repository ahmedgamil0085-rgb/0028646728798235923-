-- ==============================================================================
-- SAHALA SAAS PLATFORM - SMART & BULLETPROOF SECURITY, RLS & SCALABILITY INDEXES
-- ==============================================================================
-- هذا السكربت مخصص ومطابق 100% لجداول مشروعك الفعلية فقط:
-- 1. يحذف الجداول الإضافية غير المستخدمة (general_reviews, orders, reservations) التي أنشأها السكربت السابق.
-- 2. يفعل جدار الحماية (RLS) والفهارس السريعة (B-Tree Indexes) على جداولك الـ 20 الفعلية فقط.
-- ==============================================================================

-- أولاً: تنظيف وحذف الجداول الإضافية غير المستخدمة في متجرك
DROP TABLE IF EXISTS public.general_reviews CASCADE;
DROP TABLE IF EXISTS public.orders CASCADE;
DROP TABLE IF EXISTS public.reservations CASCADE;

-- ثانياً: دوال التحقق الأمني من ملكية المتجر عبر التوكن المشفر (JWT)
CREATE OR REPLACE FUNCTION public.get_auth_user_email()
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN COALESCE(
        auth.jwt() ->> 'email',
        current_setting('request.jwt.claim.email', true)
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.is_tenant_owner(target_tenant_id text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF target_tenant_id IS NULL OR COALESCE(get_auth_user_email(), '') = '' THEN
        RETURN false;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = 'tenants'
    ) THEN
        RETURN EXISTS (
            SELECT 1 FROM public.tenants
            WHERE tenant_id = target_tenant_id
            AND LOWER(TRIM(COALESCE(owner_email, ''))) = LOWER(TRIM(COALESCE(get_auth_user_email(), '')))
            AND (status IS NULL OR LOWER(TRIM(status)) NOT IN ('suspended', 'disabled', 'expired', 'معلق', 'محظور', 'منتهي'))
            AND (expiry_date IS NULL OR expiry_date >= CURRENT_DATE)
        );
    END IF;

    -- Fail-closed: if the tenants table does not exist, deny write access by default
    RETURN false;
END;
$$;

-- حماية حقول الاشتراك والملكية في جدول tenants من التلاعب عبر المتصفح (DevTools Privilege Escalation Guard)
CREATE OR REPLACE FUNCTION public.protect_tenant_subscription_fields()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    -- إذا كان التحديث قادماً من واجهة المتصفح (authenticated / anon) وليس من مدير المنصة (postgres / service_role)
    IF COALESCE(auth.role(), '') IN ('authenticated', 'anon') THEN
        NEW.tenant_id := OLD.tenant_id;
        NEW.owner_email := OLD.owner_email;
        NEW.status := OLD.status;
        NEW.expiry_date := OLD.expiry_date;
    END IF;
    RETURN NEW;
END;
$$;

-- ثالثاً: تفعيل الحماية (RLS) والفهارس السريعة على جداولك الـ 20 الفعلية بالضبط
DO $$
DECLARE
    tbl_name text;
    tables_list text[] := ARRAY[
        'announcements',
        'app_users',
        'brands',
        'categories',
        'coupons',
        'image_bank',
        'item_gallery',
        'item_variants',
        'menu_items',
        'privacy_sections',
        'product_reviews',
        'shared_carts',
        'site_settings',
        'store_about_info',
        'store_commitments',
        'store_contact_messages',
        'store_customer_service',
        'store_faqs',
        'store_stats',
        'tenants'
    ];
BEGIN
    FOREACH tbl_name IN ARRAY tables_list
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_name = tbl_name
        ) THEN
            -- 1. تفعيل RLS على الجدول
            EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', tbl_name);

            -- 2. إنشاء فهرس سريع (B-Tree Index) على عمود tenant_id لتحمل ملايين الزوار والسجلات
            IF EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_schema = 'public' AND table_name = tbl_name AND column_name = 'tenant_id'
            ) THEN
                EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_tenant_id ON public.%I (tenant_id);', tbl_name, tbl_name);
            END IF;

            -- 3. سياسة القراءة العامة لواجهة المتجر (Storefront Public Read)
            -- ملاحظة أمنية: جدول app_users مستثنى تماماً من القراءة العامة لحماية بيانات الحسابات وكلمات المرور
            IF tbl_name IN (
                'announcements', 'brands', 'categories', 'coupons', 'image_bank',
                'item_gallery', 'item_variants', 'menu_items', 'privacy_sections',
                'product_reviews', 'shared_carts', 'site_settings', 'store_about_info',
                'store_commitments', 'store_customer_service', 'store_faqs', 'store_stats'
            ) THEN
                EXECUTE format('DROP POLICY IF EXISTS "Public storefront select" ON public.%I;', tbl_name);
                EXECUTE format('CREATE POLICY "Public storefront select" ON public.%I FOR SELECT USING (true);', tbl_name);
            END IF;

            -- 4. سياسة الإضافة العامة للزوار من المتجر (إرسال تقييم منتج، رسالة تواصل، أو مشاركة سلة)
            IF tbl_name = 'product_reviews' THEN
                EXECUTE 'DROP POLICY IF EXISTS "Public insert allowed" ON public.product_reviews;';
                -- منع الزائر من اعتماد تقييمه لنفسه مباشرة (يجب أن يكون غير معتمد حتى يوافق عليه مالك المتجر)
                EXECUTE 'CREATE POLICY "Public insert allowed" ON public.product_reviews FOR INSERT WITH CHECK (COALESCE(is_approved, false) = false OR is_tenant_owner(tenant_id));';
            ELSIF tbl_name IN ('store_contact_messages', 'shared_carts') THEN
                EXECUTE format('DROP POLICY IF EXISTS "Public insert allowed" ON public.%I;', tbl_name);
                EXECUTE format('CREATE POLICY "Public insert allowed" ON public.%I FOR INSERT WITH CHECK (true);', tbl_name);
            END IF;

            -- 5. سياسة التحكم الكامل لمالك المتجر فقط (Tenant Owner Management Policy)
            IF tbl_name NOT IN ('tenants', 'image_bank') THEN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_schema = 'public' AND table_name = tbl_name AND column_name = 'tenant_id'
                ) THEN
                    EXECUTE format('DROP POLICY IF EXISTS "Tenant owner manage" ON public.%I;', tbl_name);
                    EXECUTE format('CREATE POLICY "Tenant owner manage" ON public.%I FOR ALL USING (is_tenant_owner(tenant_id)) WITH CHECK (is_tenant_owner(tenant_id));', tbl_name);
                END IF;
            ELSIF tbl_name = 'tenants' THEN
                EXECUTE 'DROP POLICY IF EXISTS "Owners manage own tenant" ON public.tenants;';
                EXECUTE 'DROP POLICY IF EXISTS "Owners update own tenant" ON public.tenants;';
                EXECUTE 'CREATE POLICY "Owners manage own tenant" ON public.tenants FOR SELECT USING (LOWER(TRIM(owner_email)) = LOWER(TRIM(get_auth_user_email())));';
                EXECUTE 'CREATE POLICY "Owners update own tenant" ON public.tenants FOR UPDATE USING (is_tenant_owner(tenant_id)) WITH CHECK (is_tenant_owner(tenant_id) AND LOWER(TRIM(owner_email)) = LOWER(TRIM(get_auth_user_email())));';
                EXECUTE 'DROP TRIGGER IF EXISTS trg_protect_tenant_subscription ON public.tenants;';
                EXECUTE 'CREATE TRIGGER trg_protect_tenant_subscription BEFORE UPDATE ON public.tenants FOR EACH ROW EXECUTE FUNCTION public.protect_tenant_subscription_fields();';
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_tenants_owner_email ON public.tenants (LOWER(TRIM(owner_email)));';
            END IF;

            RAISE NOTICE 'Successfully fortified and indexed table: %', tbl_name;
        END IF;
    END LOOP;

    -- 6. تعيين الصورة الافتراضية الموحدة لجميع الأقسام والمنتجات التي ليس لها صورة لكل العملاء
    ALTER TABLE IF EXISTS public.categories ALTER COLUMN image_url SET DEFAULT 'https://cdn.sahalacompany.com/placeholder.webp';
    ALTER TABLE IF EXISTS public.menu_items ALTER COLUMN image_url SET DEFAULT 'https://cdn.sahalacompany.com/placeholder.webp';

    UPDATE public.categories
    SET image_url = 'https://cdn.sahalacompany.com/placeholder.webp'
    WHERE image_url IS NULL OR TRIM(image_url) = '' OR image_url LIKE '%sahala-placeholder%';

    UPDATE public.menu_items
    SET image_url = 'https://cdn.sahalacompany.com/placeholder.webp'
    WHERE image_url IS NULL OR TRIM(image_url) = '' OR image_url LIKE '%sahala-placeholder%';
END $$;
